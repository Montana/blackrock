import sys
import json
import subprocess
import argparse
import os
import pandas as pd
import time
import boto3
from dep.input_schema import (
    label_column,
    get_feature_names,
    training_lower_term,
    training_upper_term,
    infer_term,
)

def install(package, options=[]):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package] + options)


install("snowflake-connector-python==2.7.9")
install("snowflake-sqlalchemy==1.4.0")

from sqlalchemy import create_engine

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-2"


def get_secret(secret_name):
    region_name = "ap-southeast-2"

    # Create a Secrets Manager client (Can use a KMS like Vault)
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    return get_secret_value_response["SecretString"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--snowflake-account", type=str, default=None)
    parser.add_argument("--snowflake-db", type=str, default=None)
    parser.add_argument("--snowflake-schema", type=str, default=None)
    parser.add_argument("--snowflake-warehouse", type=str, default=None)
    parser.add_argument("--snowflake-role", type=str, default=None)
    parser.add_argument("--secret-name", type=str, default=None)
    parser.add_argument("--sample", type=str, choices=["false", "true"], default=False)
    args = parser.parse_args()
    secrets = json.loads(get_secret(args.secret_name))

    # Get snowflake config
    account = args.snowflake_account
    db = args.snowflake_db
    warehouse = args.snowflake_warehouse
    role = args.snowflake_role
    schema = args.snowflake_schema
    user = secrets["USER"]
    private_key = secrets["PASS"]

    pem_prefix = "-----BEGIN RSA PRIVATE KEY-----\n"
    pem_suffix = "\n-----END RSA PRIVATE KEY-----"
    key = "{}{}{}".format(pem_prefix, private_key, pem_suffix)
    private_key = key.encode()

    p_key = serialization.load_pem_private_key(private_key, None, default_backend())

    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Setup connection to Snowflake
    conn = snowflake.connector.connect(
        account=account,
        database=db,
        schema=schema,
        user=user,
        private_key=pkb,
        role=role,
        warehouse=warehouse,
    )

    engine = create_engine(
        f"snowflake://{account}.snowflakecomputing.com", creator=lambda: conn
    )

    # Download both training and inference data for preprocessing and inheritance
    download_query = f"""
        SELECT * FROM TABLE
    """

    with engine.connect() as con:
        print("Download training data with query:", download_query)
        df = pd.read_sql(download_query, con)
    # Grab the CSV
    df.to_csv(f"/opt/ml/processing/output/raw_data.csv", index=False)
