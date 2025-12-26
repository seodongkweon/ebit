#!/bin/sh

set +e

mkdir -p /logs/verifier /data /output

# Install test dependencies
pip install --no-cache-dir \
    pytest==8.4.1 \
    pluggy==1.6.0 \
    packaging==24.2 \
    iniconfig==2.0.0

# Run pytest tests
cd /tests
pytest test_outputs.py -rA -v

RC=$?

if [ $RC -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi

exit 0
