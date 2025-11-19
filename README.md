# Tempesta WebShield

Automatic detection and blocking bad bots (DDoS, shopping bots, scrappers,
booking bots and others) by TLS and HTTP fingerprints or IP based on Tempesta FW
access logs stored in the Clickhouse database.

*The current version 0.1 is experimental and should not be used in production.*

## Wiki
* [How it works](https://tempesta-tech.com/knowledge-base/Bot-Protection/#how-it-works)
* [Installation and quick start](https://tempesta-tech.com/knowledge-base/Bot-Protection/#quick-start)
* [Configuration](https://tempesta-tech.com/knowledge-base/Bot-Protection/#historical-mode)
* [Use cases](https://tempesta-tech.com/knowledge-base/Bot-Protection/#how-to-defend-your-app)


## Requirements

- Python 3.12 <=
- [Tempesta FW](https://github.com/tempesta-tech/tempesta) 0.8.0 <=
- Clickhouse 25.6.0 <=


## Run tests

To run the tests you need to copy GeoLite2-City.mmdb to `tests/` directory.

```bash
# run all tests with a logging level INFO
pytest

# show the tests output
pytest -s

# the additional verbose level for pytest
pytest -vvv

# run debugger on the error
pytest --pdb

# run the tests from dir
pytest -s -vvv tests

# run the tests from file
pytest -s -vvv tests/test_app.py

# run the specific test
pytest -s -vvv tests/test_app.py::test_run_app

# preferred running params
pytest -s -vvv --pdb
```

## Format project
```bash
black .
isort .
```
