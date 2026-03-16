#!/bin/bash

INSTALL_PATH=/opt/tempesta/webshield
SOURCE_DIR=$INSTALL_PATH/source
PYTHON_REQUIREMENTS=$SOURCE_DIR/requirements.txt
PYTHON_VENV=$INSTALL_PATH/venv
PYTHON_ENV_ACTIVATE=$PYTHON_VENV/bin/activate
CONFIG_DIR=/etc/tempesta/webshield
CONFIG_SRC_PATH=$SOURCE_DIR/example.env
CONFIG_DST_PATH=$CONFIG_DIR/app.env
ALLOWED_USERS_DST_PATH=$CONFIG_DIR/allow_user_agents.txt
SYSTEMD_SERVICE_SRC_PATH=$SOURCE_DIR/deployment/tempesta-webshield.service
SYSTEMD_SERVICE_DST_PATH=/etc/systemd/system/tempesta-webshield.service
TEMPESTA_CONFIG_DIR=/etc/tempesta/fw
TEMPESTA_TFT_DIR=$TEMPESTA_CONFIG_DIR/tft
TEMPESTA_TFH_DIR=$TEMPESTA_CONFIG_DIR/tfh

echo "Installing Tempesta WebShield"
echo "Removing old version if it exists"
rm -rf $INSTALL_PATH

mkdir -p $SOURCE_DIR
cp -R ./* $SOURCE_DIR

echo "Installing additional requirements"
apt install -y ipset

echo "Creating Python virtual environment"
python3 -m venv $PYTHON_VENV
source $PYTHON_ENV_ACTIVATE

echo "Installing Python requirements"
pip install -r $PYTHON_REQUIREMENTS > /dev/null

echo "Copying default config if it does not exist"
mkdir -p $CONFIG_DIR
mkdir -p $TEMPESTA_TFT_DIR
mkdir -p $TEMPESTA_TFH_DIR
cp --update=none $CONFIG_SRC_PATH $CONFIG_DST_PATH
touch $ALLOWED_USERS_DST_PATH

echo "Adding systemd service"
cp $SYSTEMD_SERVICE_SRC_PATH $SYSTEMD_SERVICE_DST_PATH
systemctl daemon-reload
systemctl enable tempesta-webshield.service

echo "Installation Complete!"
