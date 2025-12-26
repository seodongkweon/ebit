#!/bin/sh

set +e

mkdir -p /logs/verifier /data /output

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
