#!/bin/bash

set -ex

echo "[entrypoint.sh] Running with command '$*'";

if [ -z "$PORT" ]; then
    export PORT=8000
fi

if [ "$1" = "local" ]; then
    uvicorn --host 0.0.0.0 --port $PORT api.main:app
elif [ "$1" = "prod" ]; then
    # Run the web service on container startup. Here we use the uvicorn
    # webserver, with NUM_OF_UVICORN_WORKERS worker process.
    # For environments with multiple CPU cores, increase the number of workers
    # to be equal to the cores available.
    # Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
    gunicorn --worker-class uvicorn.workers.UvicornWorker --threads 8 --timeout 0 --bind 0.0.0.0:$PORT --workers ${NUM_OF_UVICORN_WORKERS:-1} --log-level ${LOG_LEVEL:-warning} --forwarded-allow-ips="*" --proxy-protocol api.main:app
elif [ "$1" = "test" ]; then
    # Clean the code
    if [ "$2" = "local" ]; then
      isort .
      black .
    else
      isort --check .
      black --check .
    fi
    flake8 .
    # Test the code
    pytest --cov tests/ --numprocesses ${NUM_CPU_FOR_TESTS:-auto}
    coverage report
    coverage erase
elif [ "$1" = "outdated" ]; then
  # Check for updated packages
  pip list --outdated
else
    echo "Unknown command: '$1'";
    echo "Exiting!";
    exit 1;
fi
