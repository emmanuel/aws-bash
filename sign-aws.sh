#!/bin/bash

# http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# Steps:
# 1. Create a canonical request: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#     CanonicalRequest =
#       HTTPRequestMethod + '\n' +
#       CanonicalURI + '\n' +
#       CanonicalQueryString + '\n' +
#       CanonicalHeaders + '\n' +
#       SignedHeaders + '\n' +
#       HexEncode(Hash(RequestPayload))
# 2. Create a string to sign: http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
#     StringToSign  =
#       Algorithm + '\n' +
#       RequestDate + '\n' +
#       CredentialScope + '\n' +
#       HashedCanonicalRequest))
# 3. Create a signature: http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#     kSecret = Your AWS Secret Access Key
#     kDate = HMAC("AWS4" + kSecret, Date)
#     kRegion = HMAC(kDate, Region)
#     kService = HMAC(kRegion, Service)
#     kSigning = HMAC(kService, "aws4_request")

# from: http://stackoverflow.com/a/9323166
sha256_hash(){
  a="$@"
  printf "$a" | openssl dgst -binary -sha256
}
sha256_hash_in_hex(){
  a="$@"
  printf "$a" | openssl dgst -binary -sha256 | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}
# adapted from: http://stackoverflow.com/questions/7285059/hmac-sha1-in-bash
# and also this answer there: http://stackoverflow.com/a/22369607
function hex_of_sha256_hmac_with_string_key_and_value {
  KEY=$1
  DATA="$2"
  shift 2
  printf "$DATA" | openssl dgst -binary -sha256 -hmac "$KEY" | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}
function hex_of_sha256_hmac_with_hex_key_and_value {
  KEY="$1"
  DATA="$2"
  shift 2
  printf "$DATA" | openssl dgst -binary -sha256 -mac HMAC -macopt "hexkey:$KEY" | od -An -vtx1 | sed 's/[ \n]//g' | sed 'N;s/\n//'
}

# adapted from: http://danosipov.com/?p=496
function sign() {
  STRING_TO_SIGN="$1"
  SECRET_ACCESS_KEY="$2"
  REQUEST_DATE="$3"
  REQUEST_REGION="$4"
  REQUEST_SERVICE="$5"
  shift 5

  DATE_HMAC=$(hex_of_sha256_hmac_with_string_key_and_value "AWS4${SECRET_ACCESS_KEY}" ${REQUEST_DATE})
  REGION_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${DATE_HMAC}" ${REQUEST_REGION})
  SERVICE_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${REGION_HMAC}" ${REQUEST_SERVICE})
  SIGNING_HMAC=$(hex_of_sha256_hmac_with_hex_key_and_value "${SERVICE_HMAC}" "aws4_request")
  SIGNATURE=$(hex_of_sha256_hmac_with_hex_key_and_value "${SIGNING_HMAC}" "${STRING_TO_SIGN}")

  printf "${SIGNATURE}"
}

function create_canonical_request() {
  HTTP_REQUEST_METHOD="$1"
  CANONICAL_URL="$2"
  CANONICAL_QUERY_STRING="$3"
  CANONICAL_HEADERS="$4"
  SIGNED_HEADERS="$5"
  REQUEST_PAYLOAD="$6"
  shift 6

  REQUEST_PAYLOAD_HASH_HEX=$(sha256_hash_in_hex "${REQUEST_PAYLOAD}")
  CANONICAL_REQUEST_CONTENT="${HTTP_REQUEST_METHOD}\n${CANONICAL_URI}\n${CANONICAL_QUERY_STRING}\n${CANONICAL_HEADERS}\n\n${SIGNED_HEADERS}\n${REQUEST_PAYLOAD_HASH_HEX}"
  CANONICAL_REQUEST=$(sha256_hash_in_hex "${CANONICAL_REQUEST_CONTENT}")

  printf "$CANONICAL_REQUEST"
}

function sign_canonical_request() {
  CANONICAL_REQUEST="$1"
  SECRET_ACCESS_KEY="$2"
  REQUEST_TIME="$3"
  REGION="$4"
  REQUEST_SERVICE="$5"
  shift 5

  REQUEST_DATE=$(printf "${REQUEST_TIME}" | cut -c 1-8)
  ALGORITHM=AWS4-HMAC-SHA256
  CREDENTIAL_SCOPE="${REQUEST_DATE}/${REQUEST_REGION}/${REQUEST_SERVICE}/aws4_request"
  STRING_TO_SIGN="${ALGORITHM}\n${REQUEST_TIME}\n${CREDENTIAL_SCOPE}\n${CANONICAL_REQUEST}"

  printf $(sign $STRING_TO_SIGN $SECRET_ACCESS_KEY $REQUEST_DATE $REGION $REQUEST_SERVICE)
}

# Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c
function create_authorization_header() {
  ACCESS_KEY_ID=$1
  SIGNATURE=$2
  REQUEST_TIME=$3
  REQUEST_REGION=$4
  REQUEST_SERVICE=$5
  shift 5

  REQUEST_DATE=$(printf "${REQUEST_TIME}" | cut -c 1-8)
  ALGORITHM=AWS4-HMAC-SHA256
  CREDENTIAL_SCOPE="${REQUEST_DATE}/${REQUEST_REGION}/${REQUEST_SERVICE}/aws4_request"

  printf "$ALGORITHM \
Credential=$ACCESS_KEY_ID/$REQUEST_DATE/$REGION/$SERVICE/aws4_request, \
SignedHeaders=content-type;host;x-amz-date, \
Signature=$SIGNATURE"
}

# CREDENTIALS_JSON Looks like this:
# {
#   "Code" : "Success",
#   "LastUpdated" : "2014-07-04T07:33:00Z",
#   "Type" : "AWS-HMAC",
#   "AccessKeyId" : "ASIAJ3DRAU6NZNGMSQTQ",
#   "SecretAccessKey" : "Yx2Ai3NnYsOmDC5fvCHsfyf5qrAxdK7WddAFKfK/",
#   "Token" : "AQoDYXdzEFka0AO9/3FHdC250guR4k6heCTag93o1scxNg7iqBLz7GMIxacwTQXmiBLibGlEttlHatQ0y/8FhNFHdbKWUT9eSuypHYlNpZnqNbu5hOkLy/Oginx3n+uTr6WxiMsV01NRox5Mt78uMSweJRQXuglkRWieKmu1DXdPmgQPb7ByPqVtnAkNKybHeaqViuqLnkIe0Uh0R5aWSH5AvMCZ10+ey5tgtyzO3aN7fmdbDIhtNxV5XGSVqySTHGVFh0fUO4i/rIVg5smX5Ca0LDK0JziXe7+xDvMIG3Ru3EbWB/EqQatTaY1ofLkWX9pG9NWqslz9IwCSO1zHOvudDU60kpFBGXxnNSfIKZ1N96EpbeQ5NU8d/8EMaRP2k/PVhmKuQEMmVBkMNHdoamULNlAp+8wiv69dpQnpQJcB6WyiE3NVZyqPnFcGvWwZbQJQeIFjH9U+Tt64AA57NPWmWJG/A8KTLFLy/zqsPr14wpLY/tNN9gyiKTAk54vOQxYfy+ACI2qZw3Rf6Do/SsJ2eW2ZFeLxFUor382T5nGF7/7GcDyib9pM4pwNSnxVsJiCEoapiDoPggIrJnmTau82mXjNc4oPPw11mXUx+6njbUaahkwvgso/9yC3sdmdBQ==",
#   "Expiration" : "2014-07-04T13:55:44Z"
# }
function get_details_for_security_credential() {
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$SECURITY_CREDENTIAL_NAME
}

function get_access_key_id_for_security_credential() {
  SECURITY_CREDENTIAL_NAME=$1
  CREDENTIALS_JSON=${CREDENTIALS_JSON:$(get_details_for_security_credential $SECURITY_CREDENTIAL_NAME)}
  CREDENTIALS_JSON=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$SECURITY_CREDENTIAL_NAME)

  printf "$CREDENTIALS_JSON" | grep AccessKeyId | awk -F: '{print $2}' | sed 's/^\s\+\"\(.\+\)\".\+$/\1/'
}

function get_secret_access_key_for_security_credential() {
  SECURITY_CREDENTIAL_NAME=$1
  CREDENTIALS_JSON=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$SECURITY_CREDENTIAL_NAME)

  printf "$CREDENTIALS_JSON" | grep SecretAccessKey | awk -F: '{print $2}' | sed 's/^\s\+\"\(.\+\)\".\+$/\1/'
}

function get_instance_id() {
  printf $(curl -s http://169.254.169.254/latest/meta-data/instance-id)
}

# POST https://elasticloadbalancing.us-west-2.amazonaws.com/ HTTP/1.1
# content-type:application/x-www-form-urlencoded; charset=utf-8
# host:elasticloadbalancing.us-west-2.amazonaws.com
#
# Action=RegisterInstancesWithLoadBalancer\
# &Instances.member.1.InstanceId=$INSTANCE_ID\
# &LoadBalancerName=$LOAD_BALANCER_NAME\
# &AUTHPARAMS\
# &Version=2012-06-01


# 1. Create a canonical request:
ACCESS_KEY_ID=$(get_access_key_id_for_security_credential "coreos-beta-elb-registration")
SECRET_ACCESS_KEY=$(get_secret_access_key_for_security_credential "coreos-beta-elb-registration")
INSTANCE_ID=$(get_instance_id)
# LOAD_BALANCER_NAME=accelerator-openam
# REQUEST_TIME=$(date +%Y%m%d'T'%H%M%S'Z')
# REQUEST_REGION=us-west-2
# REQUEST_SERVICE=elb

HTTP_REQUEST_METHOD=POST
CANONICAL_URI=/
CANONICAL_QUERY_STRING=
# CANONICAL_HEADERS="content-type:application/x-www-form-urlencoded;charset=utf-8\nhost:elasticloadbalancing.${REQUEST_REGION}.amazonaws.com\nx-amz-date:${REQUEST_TIME}"
# SIGNED_HEADERS="content-type;host;x-amz-date"
# REQUEST_PAYLOAD="Action=RegisterInstancesWithLoadBalancer&Instances.member.1.InstanceId=${INSTANCE_ID}&LoadBalancerName=${LOAD_BALANCER_NAME}&Version=2012-06-01"


SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REQUEST_TIME=20110909T233600Z
REQUEST_REGION=us-east-1
REQUEST_SERVICE=iam
# HTTP_REQUEST_METHOD=POST
# CANONICAL_URI=/
# CANONICAL_QUERY_STRING=
CANONICAL_HEADERS="content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:${REQUEST_TIME}"
SIGNED_HEADERS="content-type;host;x-amz-date"
REQUEST_PAYLOAD="Action=ListUsers&Version=2010-05-08"

echo "REQUEST_TIME=$REQUEST_TIME"
echo "AUTHORIZATION_HEADER=$AUTHORIZATION_HEADER"
echo "INSTANCE_ID=$INSTANCE_ID"

CANONICAL_REQUEST=$(create_canonical_request "$HTTP_REQUEST_METHOD" "$CANONICAL_URL" "$CANONICAL_QUERY_STRING" "$CANONICAL_HEADERS" "$SIGNED_HEADERS" "$REQUEST_PAYLOAD")
SIGNATURE=$(sign_canonical_request "$CANONICAL_REQUEST" "$SECRET_ACCESS_KEY" "$REQUEST_TIME" "$REQUEST_REGION" "$REQUEST_SERVICE")
AUTHORIZATION_HEADER=$(create_authorization_header $ACCESS_KEY_ID $SIGNATURE $REQUEST_TIME $REQUEST_REGION $REQUEST_SERVICE)

echo "SIGNATURE=$SIGNATURE"
echo "AUTHORIZATION_HEADER=$AUTHORIZATION_HEADER"
echo "INSTANCE_ID=$INSTANCE_ID"
echo "ACCESS_KEY_ID=$ACCESS_KEY_ID"
echo "SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY"

# curl -XPOST \
#   -H "content-type:application/x-www-form-urlencoded; charset=utf-8" \
#   -H "host:elasticloadbalancing.us-west-2.amazonaws.com" \
#   -H "x-amz-date:$REQUEST_TIME" \
#   -H "authorization: $AUTHORIZATION_HEADER" \
#   -d 'Action=RegisterInstancesWithLoadBalancer\
# &Instances.member.1.InstanceId=$INSTANCE_ID\
# &LoadBalancerName=$LOAD_BALANCER_NAME\
# &Version=2012-06-01' \
#   https://elasticloadbalancing.us-west-2.amazonaws.com/
