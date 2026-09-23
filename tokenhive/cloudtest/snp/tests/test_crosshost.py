"""Local tests for the cross-host deploy's whitelist plumbing. No AWS, no network.

The Hub admits agents and advertises /v1/policies from a whitelist, and the
enclave enforces one. They have to be the same document, and it has to be the
document the running app was measured with. Two ways that broke, both by hand:

(1) deploy uploaded the whitelist to ~/policy but started the Hub with
    -policy-dir $HOME/tee/policy, so on a clean host the Hub loaded no policy at
    all and refused every agent registration;
(2) deploy took the current build's policy file, so rebuilding for a newer
    whitelist and then deploying an instance launched earlier handed the Hub
    rules the enclave was not running.

These tests hold the properties that fix depends on: one place says where the
whitelist lives, deploy derives it from the running app's bundle, and the
bundle it picks is verified rather than trusted from its filename.
"""

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # snp/tests
SNP = _DIR.parent                                # snp
REPO = _DIR.parents[3]                           # reclaim-tee
CROSSHOST = SNP / "crosshost.sh"
SRC = CROSSHOST.read_text()


def _shell_function(name):
    """The literal text of a top-level shell function, so the tests exercise the
    real code rather than a copy that can drift from it."""
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", SRC, re.M | re.S)
    if not m:
        raise AssertionError(f"no {name}() in {CROSSHOST}")
    return m.group(0)


class WhitelistLocationTest(unittest.TestCase):
    """Where deploy puts the whitelist and where it tells the Hub to read it."""

    def test_one_name_decides_where_the_whitelist_lives(self):
        # The bug was two hand-written paths for one location. They now derive
        # from a single variable, so this asserts the variable is the only
        # definition and that both users go through it.
        self.assertEqual(SRC.count('REMOTE_POLICY_REL="'), 1,
                         "REMOTE_POLICY_REL must be defined exactly once")
        self.assertNotIn("tee/policy", SRC,
                         "a hardcoded policy path is how the upload and -policy-dir drifted apart")
        self.assertIn('mkdir -p tee mtls ${REMOTE_POLICY_REL}', SRC)
        self.assertIn('"${REMOTE_POLICY_REL}/policy.cbor" >/dev/null', SRC,
                      "the whitelist upload must land in the shared location")
        self.assertIn('-policy-dir "\\$HOME/${REMOTE_POLICY_REL}"', SRC,
                      "the Hub's -policy-dir must be that same location")


class DeployWhitelistVersionTest(unittest.TestCase):
    """Which build's whitelist deploy ships."""

    def test_deploy_uses_the_running_apps_bundle(self):
        body = _shell_function("cmd_deploy")
        self.assertIn('archived_bundle "${app_hash}"', body,
                      "deploy must resolve the whitelist by the attested app identity")
        self.assertNotIn("POLICY_DIR", body,
                         "the current build's policy dir does not say which app is running")

    def test_every_build_archives_its_bundle(self):
        # The lookup above can only work if a build files its bundle under the
        # digest it measures.
        self.assertEqual(SRC.count('archive_bundle "${bundle}" "${digest}"'), 2,
                         "both build and build-single must archive")

    def test_deploy_refuses_when_no_bundle_measures_the_running_app(self):
        body = _shell_function("cmd_deploy")
        self.assertIn("exit 1", body)
        self.assertIn("no archived bundle measuring", body)


class AppIdentityTest(unittest.TestCase):
    """Which app identity gets pinned, and where that identity comes from.

    deploy resolves the whitelist by the app_hash in state, so a state file that
    records a digest the launched image does not measure would defeat the whole
    scheme: the pair (recorded digest, archived policy) is internally consistent
    even when both describe a different build than the enclave is running. The
    recorded identity therefore has to come from the image itself.
    """

    def test_up_records_the_launched_images_own_digest(self):
        body = _shell_function("cmd_up")
        self.assertIn('ami_app_digest "${a}"', body,
                      "up must read the digest off the AMI it launched")
        self.assertNotIn("pack.sh digest", body,
                         "re-hashing bin/ can name a build the launched AMI does not embed")

    def test_images_carry_the_digest_they_embed(self):
        src = (REPO / "deploy" / "snp-build.sh").read_text()
        m = re.search(r"ec2 register-image.*?--output text\)", src, re.S)
        self.assertIsNotNone(m, "no register-image call found")
        # The value must be the bare sha256. "snp-app:" is the app-identity
        # prefix up adds when it pins the TEE, so tagging the image with the
        # prefixed form would name an identity no image can ever satisfy.
        self.assertIn("{Key=snp-app,Value=${DIGEST#snp-app:}}", m.group(0),
                      "the tag value must be the digest the image embeds, unprefixed")

    def test_up_pins_the_image_before_paying_for_it(self):
        # The tag is the only thing that can pin the run, so an image without
        # one has to be refused before an instance is bought for it.
        body = _shell_function("cmd_up")
        self.assertLess(body.index('ami_app_digest "${a}"'),
                        body.index('crosshost.py "${a}"'),
                        "up must read the image's tag before launching it")

    def test_up_records_the_identity_in_state(self):
        # deploy resolves the whitelist by tee.app_hash in crosshost.json, so up
        # has to write it there — and only after the launch, because
        # crosshost.py is what creates the tee record that write merges into.
        body = _shell_function("cmd_up")
        self.assertRegex(body, r"p\['tee'\]\['app_hash'\]\s*=")
        self.assertIn("${HOSTS}", body)
        self.assertGreater(body.index("p['tee']['app_hash']"),
                           body.index('crosshost.py "${a}"'),
                           "the identity is recorded once the instance exists")

    def test_a_missing_tag_is_refused_rather_than_guessed(self):
        body = _shell_function("ami_app_digest")
        self.assertIn("no snp-app tag", body)
        self.assertIn("sys.exit", body)
        # No fallback that would re-introduce the guess this replaces.
        self.assertNotIn("sha256sum", body)


class ArchivedBundleTest(unittest.TestCase):
    """archived_bundle is the gate: it must not hand back a bundle on trust."""

    def _run(self, bundles_dir, app_hash):
        script = "set -euo pipefail\n" + _shell_function("archived_bundle") + "\n"
        script += f'BUNDLES_DIR={bundles_dir}\narchived_bundle {app_hash}\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_returns_the_bundle_that_measures_the_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = b"the-bundle-the-enclave-measures"
            digest = hashlib.sha256(payload).hexdigest()
            archive = Path(tmp) / f"{digest}.tar"
            archive.write_bytes(payload)

            out = self._run(tmp, digest)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout.strip(), str(archive))

    def test_refuses_a_bundle_that_does_not_measure_the_digest(self):
        # The filename claims the digest; the contents are not the app that
        # digest names. Trusting the name here would hand the Hub a whitelist
        # from some other build.
        with tempfile.TemporaryDirectory() as tmp:
            claimed = "0" * 64
            (Path(tmp) / f"{claimed}.tar").write_bytes(b"a different build")

            out = self._run(tmp, claimed)
            self.assertNotEqual(out.returncode, 0,
                                "a tampered/wrong bundle must not be accepted")
            self.assertEqual(out.stdout.strip(), "")

    def test_refuses_when_nothing_was_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._run(tmp, "1" * 64)
            self.assertNotEqual(out.returncode, 0)
            self.assertEqual(out.stdout.strip(), "")


class SwapWiringTest(unittest.TestCase):
    """`up --new` / `down --superseded`: the shell half of the no-wait swap.

    The swap's safety lives in crosshost.py and retire.py, but the operator
    reaches both through these two shells — and a flag that is accepted and then
    dropped is silent: `up --new` without --new quietly becomes "adopt whatever
    is recorded", which is the very thing the swap was written to avoid.
    """

    def test_up_parses_and_forwards_new(self):
        body = _shell_function("cmd_up")
        self.assertIn('new_arg="--new"', body)
        self.assertIn("${new_arg}", body,
                      "--new must reach crosshost.py, not just be accepted here")

    def test_down_superseded_delegates_to_retire_py(self):
        body = _shell_function("cmd_down")
        self.assertIn("retire.py", body)
        self.assertIn('--state "${HOSTS}"', body)
        # Its only narrowing is the recorded superseded set; the tag-wide
        # delete.py must not be reachable on that path.
        self.assertNotIn("delete.py", body[body.index("--superseded"):body.index("if [[ -z \"${tee_only}\"")])

    def test_down_keeps_the_two_narrowings_apart(self):
        body = _shell_function("cmd_down")
        self.assertIn("mutually exclusive", body)

    def test_console_dump_asks_for_the_latest_output(self):
        # Without Latest=True get_console_output returns a stale buffer, so a TEE
        # that came up after boot looks like one that never logged again — the
        # check a swap leans on to decide the new enclave is serving.
        body = _shell_function("dump_tee_console")
        self.assertIn("Latest=True", body)


if __name__ == "__main__":
    unittest.main()
