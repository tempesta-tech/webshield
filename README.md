# Tempesta WebShield

Block users by TFT, TFH, or IP based on Tempesta FW access 
logs stored in the ClickHouse database.

[**WIKI**](https://tempesta-tech.com/knowledge-base/Bot-Protection/)

# How to run

### Requirements:

- Python 3.12 <=
- [Tempesta FW](https://github.com/tempesta-tech/tempesta) 0.8.0 <=
- Clickhouse 25.6.0 <=

### Run manually
```bash
python3 -m venv tempesta-webshield
source tempesta-webshield/bin/activate
pip install -r requirements.txt
cp example.env /etc/tempesta-webshield/app.env
touch /etc/tempesta-webshield/allow_user_agents.txt
python3 app.py 
```

### Run tests
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

### Format project
```bash
black .
isort .
```

# How to block

### Prepare Tempesta FW config
It's useful to define separate directories for different groups of TF hashes  
in the Tempesta FW configuration file (/etc/tempesta/tempesta_fw.conf).
```nginx
tft {
    !include /etc/tempesta/tft/
}
tfh {
    !include /etc/tempesta/tfh/
}
```
Then add 2 files
- /etc/tempesta/tft/blocked.conf
- /etc/tempesta/tfh/blocked.conf

These files should be used by default by the WebShield 
to add new blocking hashes.
