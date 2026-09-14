module github.com/reclaimprotocol/reclaim-tee

go 1.27

toolchain go1.27.0

require (
	cloud.google.com/go/firestore v1.25.0
	cloud.google.com/go/kms v1.33.0
	cloud.google.com/go/logging v1.19.1
	cloud.google.com/go/secretmanager v1.21.0
	filippo.io/nistec v0.0.4
	github.com/KGKallasmaa/countries v0.2.0
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/config v1.32.37
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.82.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.6
	github.com/consensys/gnark v0.16.0
	github.com/consensys/gnark-crypto v0.21.0
	github.com/coreos/go-json v0.0.0-20231102161613-e49c8866685a
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/fxamacker/cbor/v2 v2.9.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-eventlog v0.0.3-0.20260617163629-883cc5652c69
	github.com/google/go-sev-guest v0.15.0
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.9
	github.com/gorilla/websocket v1.5.3
	github.com/joho/godotenv v1.5.1
	github.com/markkurossi/mpc v0.0.0-20260616034910-9c484ce016a7
	github.com/mr-tron/base58 v1.3.0
	github.com/reclaimprotocol/jsonpathplus-go/v2 v2.0.1
	github.com/reclaimprotocol/xpath-go v1.7.0
	github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20260526062330-40c74b9e1c9f
	github.com/xeipuuv/gojsonschema v1.2.0
	go.mozilla.org/pkcs7 v0.10.0
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.55.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/text v0.41.0
	golang.org/x/time v0.15.0
	google.golang.org/api v0.293.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
	modernc.org/sqlite v1.32.0
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.23.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.13.0 // indirect
	cloud.google.com/go/longrunning v1.2.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260706204617-c9f710ef3461 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.36 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.6 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
	github.com/bits-and-blooms/bitset v1.25.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.21 // indirect
	github.com/googleapis/gax-go/v2 v2.23.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/markkurossi/crypto v0.0.0-20240520115340-daed3f9a1082 // indirect
	github.com/markkurossi/tabulate v0.0.0-20251126123558-a08056f6160f // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.70.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.70.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20260813180055-c1d0aacb2297 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	google.golang.org/genproto v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)

replace (
	github.com/consensys/gnark v0.16.0 => github.com/consensys/gnark v0.14.0
	github.com/consensys/gnark-crypto v0.21.0 => github.com/consensys/gnark-crypto v0.19.2
	github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20260526062330-40c74b9e1c9f => github.com/reclaimprotocol/zk-symmetric-crypto/gnark v0.0.0-20251205140100-6fd752973b8f
)
