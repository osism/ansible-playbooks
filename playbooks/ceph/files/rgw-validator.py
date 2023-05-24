#!/usr/bin/env python3
import os
import argparse
import uuid
import urllib3
import boto3
from botocore.exceptions import ClientError

def test_list_buckets():
    global client
    global test_failure
    buckets = []
    try:
        for bucket in client.buckets.all():
            buckets.append({
                        "bucket_name": bucket.name,
                        "creation_date": str(
                            bucket.creation_date.strftime(
                                "%m/%d/%Y, %H:%M:%S"
                                )
                            )
                        })
        return {
                "test_name": "s3-list-buckets",
                "result": "passed",
                "data": buckets
                }
    except Exception as err:
        test_failure = True
        return {
                "test_name": "s3-list-buckets",
                "result": "failed",
                "data": str(err)
                }

def test_create_bucket(bucket_name):
    global client
    global test_failure
    try:
        client.create_bucket(Bucket = bucket_name)
        return {
                "test_name": "s3-create-bucket",
                "result": "passed",
                "data": bucket_name
                }
    except Exception as err:
        test_failure = True
        return {
                "test_name": "s3-create-bucket",
                "result": "failed",
                "data": str(err)
                }

def test_list_bucket_content(bucket_name):
    global client
    global test_failure
    bucket_objects = []
    try:
        objects = client.Bucket(bucket_name).objects.all()
        for obj in objects:
            bucket_objects.append(obj.key)
        return {
                "test_name": "s3-list-bucket-content",
                "result": "passed",
                "data": bucket_objects
                }
    except Exception as err:
        test_failure = True
        return {
                "test_name": "s3-list-bucket-content",
                "result": "failed",
                "data": str(err)
                }

def test_create_object(bucket_name, obj_key, obj_data):
    global client
    global test_failure
    try:
        object = client.Object(bucket_name, obj_key)
        object.put(Body = obj_data)
        return {
                "test_name": "s3-create-object",
                "result": "passed",
                "data": {
                    "object_key": obj_key,
                    "object_data": obj_data
                    }
                }
    except Exception as err:
        test_failure = True
        return {
                "test_name": "s3-create-object",
                "result": "failed",
                "data": str(err)
                }

def test_read_object(bucket_name, obj_key, obj_data):
    global client
    global test_failure
    try:
        object = client.Object(bucket_name, obj_key)
        object_data = object.get()["Body"].read()
        
        # Test if read object data matches the data written
        # by test_create_object. Not perfect but for now it works.
        assert object_data.decode() == obj_data,\
            "Read object data does not match expected result. "\
            "Expected: '{}'\nGot: '{}'"\
            .format(obj_data, obj_data.decode())
        return {
                "test_name": "s3-read-object",
                "result": "passed",
                "data": {
                    "test_reason":
                        "Read object data matches expected result.",
                    "object_key":
                        obj_key,
                    "object_data":
                        object.get()["Body"].read()
                    }
                }
    except Exception as err:
        test_failure = True
        return {
                "test_name": "s3-read-object",
                "result": "failed",
                "data": str(err)
                }

def main():
    try:
        global client
        global test_failure
        test_failure = False

        # Read environment vars if set
        ENV_VALIDATOR_ENDPOINT = os.environ.get(
                    'VALIDATOR_ENDPOINT'
                )
        ENV_VALIDATOR_ACCESS_KEY = os.environ.get(
                    'VALIDATOR_ACCESS_KEY'
                )
        ENV_VALIDATOR_SECRET_KEY = os.environ.get(
                    'VALIDATOR_SECRET_KEY'
                )
        ENV_VALIDATOR_BUCKET = os.environ.get(
                    'VALIDATOR_BUCKET',
                    'osism-rgw-validator-testbucket'
                )

        # Configure argument parser
        parser = argparse.ArgumentParser(
                epilog='''Endpoint, Access Key ID, Secret access key
                and bucket may also be specified via the environment
                variables VALIDATOR_ENDPOINT, VALIDATOR_ACCESS_KEY,
                VALIDATOR_SECRET_KEY and/or VALIDATOR_BUCKET'''
                )
        parser.add_argument(
                "-k",
                "--insecure",
                help="Disable TLS certificate verification",
                action="store_true"
                )
        parser.add_argument(
                "--endpoint",
                default=ENV_VALIDATOR_ENDPOINT,
                required=ENV_VALIDATOR_ENDPOINT is None,
                help="Endpoint URL e.g. http[s]://host.name[:<port>]"
                )
        parser.add_argument(
                "--access_key",
                default=ENV_VALIDATOR_ACCESS_KEY,
                required=ENV_VALIDATOR_ACCESS_KEY is None,
                help="S3 Access Key ID"
                )
        parser.add_argument(
                "--secret_key",
                default=ENV_VALIDATOR_SECRET_KEY,
                required=ENV_VALIDATOR_SECRET_KEY is None,
                help="S3 Secret access key"
                )
        parser.add_argument(
                "--bucket",
                default=ENV_VALIDATOR_BUCKET,
                required=False,
                help="Name of bucket for testing"
                )

        # Parse arguments
        args = parser.parse_args()

        # Set variables using "constant" naming for better readability
        VALIDATOR_ENDPOINT=args.endpoint
        VALIDATOR_ACCESS_KEY=args.access_key
        VALIDATOR_SECRET_KEY=args.secret_key
        VALIDATOR_BUCKET=args.bucket
        VALIDATOR_NO_VERIFY_CERT=args.insecure

        # Disable insecure warning if validation is disabled
        if VALIDATOR_NO_VERIFY_CERT:
            urllib3.disable_warnings(
                    urllib3.exceptions.InsecureRequestWarning
                    )

        # Create boto3 S3 client
        client = boto3.resource(
                's3',
                endpoint_url = VALIDATOR_ENDPOINT,
                aws_access_key_id = VALIDATOR_ACCESS_KEY,
                aws_secret_access_key = VALIDATOR_SECRET_KEY,
                verify = not VALIDATOR_NO_VERIFY_CERT
                )
        
        test_object_name = str(uuid.uuid4())
        test_object_data = str(uuid.uuid4())

        test_results = []

        test_results.append(test_create_bucket(VALIDATOR_BUCKET))
        test_results.append(test_list_buckets())
        test_results.append(test_list_bucket_content(VALIDATOR_BUCKET))
        test_results.append(
            test_create_object(
                    VALIDATOR_BUCKET,
                    test_object_name,
                    test_object_data
                )
            )
        test_results.append(test_list_bucket_content(VALIDATOR_BUCKET))
        test_results.append(
            test_read_object(
                    VALIDATOR_BUCKET,
                    test_object_name,
                    test_object_data
                )
            )

        print(test_results);
        if test_failure:
            exit(1)
        else:
            exit(0)
    except ClientError as err:
        print("[{'client_error': '{}'}]".format(err))
        exit(1)

if __name__ == "__main__":
    main()
