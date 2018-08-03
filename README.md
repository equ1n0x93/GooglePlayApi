# GooglePlayApi
Python api for google play android store.
Updated google OAuth authentication and protobuf schemes

Available thanks to egirault great work and original repo https://github.com/egirault/googleplay-api

## Requirements:
pip install -r requirements.txt

In order to create/add new messages for the protobuf format, you need to generate a new googleplay_pb.py file, to do so edit googleplay.proto and then run:
protoc -I=<path to this repo> --python_out=<output path> <fullpath of googleplay.proto file>
Ans replace the created googleplay_pb2.py with the new created file.

## Usage example
from googleplay_importer_api import GooglePlayApi

client = GooglePlayApi(androidId=<Android Device ID>, email=<Google account username/email>, password=<Google account password>)
client.login()
client.details(packageName='com.google.android.googlequicksearchbox')

** <Android Device ID> - Android GSF ID
