"""The confidential launch's IAM instance profile. No AWS, no network.

On AWS the TEE's structured logger ships to CloudWatch Logs with the instance
role, so a confidential instance launched without a profile cannot ship a log:
the SDK builds its client happily and every ship is dropped, leaving a serial
console a few minutes deep as the only channel. TOKENHIVE_TEE_INSTANCE_PROFILE
is how the launch carries one.

The property worth pinning is the *absence* of the key when nothing is named.
IamInstanceProfile is fixed at RunInstances, and boto3 rejects
{"Name": ""} — so "no profile" has to stay the shape of a launch that never
asked for one, not a profile whose name happens to be empty.
"""

import sys
import unittest
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # snp/tests
CLOUDTEST = _DIR.parent.parent                   # cloudtest
SNP = _DIR.parent                                # snp
sys.path.insert(0, str(CLOUDTEST))
sys.path.insert(0, str(SNP))

import crosshost                                # noqa: E402
from config import Config                       # noqa: E402


class _FakeEC2:
    """Minimal stand-in capturing the RunInstances request verbatim."""

    def __init__(self):
        self.last_run = None

    def run_instances(self, **kwargs):
        self.last_run = kwargs
        return {"Instances": [{"InstanceId": "i-tee", "State": {"Name": "pending"}}]}


def _launch(profile: str):
    fake = _FakeEC2()
    crosshost.run_confidential(
        fake, Config(user="chenxinghao"), "ami-9", "vpc-1", "subnet-1", "sg-1",
        "TEE_PLATFORM=sevsnp\n", profile,
    )
    return fake.last_run


class ConfidentialLaunchProfileTest(unittest.TestCase):
    def test_no_profile_leaves_the_key_out_entirely(self):
        run = _launch("")
        self.assertNotIn("IamInstanceProfile", run,
                         "an unnamed profile must not become IamInstanceProfile={'Name': ''}")
        # The rest of the launch is unaffected: still a confidential instance.
        self.assertEqual(run["CpuOptions"], {"AmdSevSnp": "enabled"})
        self.assertTrue(run["UserData"])

    def test_named_profile_rides_into_the_launch(self):
        run = _launch("tokenhive-tee-logs")
        self.assertEqual(run["IamInstanceProfile"], {"Name": "tokenhive-tee-logs"})

    def test_env_name_is_the_one_the_docs_and_example_advertise(self):
        """The name is an operator-facing contract: it lives in .env.example and
        the deploy manual, not only in the code. Drift between them would leave an
        operator setting a variable nothing reads."""
        name = crosshost.TEE_PROFILE_ENV
        self.assertEqual(name, "TOKENHIVE_TEE_INSTANCE_PROFILE")
        self.assertIn(name, (CLOUDTEST / ".env.example").read_text())


if __name__ == "__main__":
    unittest.main()
