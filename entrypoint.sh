#!/bin/bash

set -ex

echo "[entrypoint.sh] Running with command '$*'";

if [ -z "$PORT" ]; then
    export PORT=8000
fi

if [ "$1" = "local" ]; then
    flask run --host=0.0.0.0 -p $PORT
elif [ "$1" = "prod" ]; then
    # Run the web service on container startup. Here we use the gunicorn
    # webserver, with NUM_OF_WORKERS worker process and 8 threads.
    # For environments with multiple CPU cores, increase the number of workers
    # to be equal to the cores available.
    # Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
    gunicorn --bind 0.0.0.0:$PORT --workers ${NUM_OF_GUNICORN_WORKERS:-1} --threads 8 --timeout 0 --log-level ${LOG_LEVEL:-warning} api.main:app
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
else
    echo "Unknown command: '$1'";
    echo "Exiting!";
    exit 1;
fi
