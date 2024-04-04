import os

# Stages
STAGING = "stage"
PRODUCTION = "prod"

# Environment variables
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
REGION = os.environ.get("REGION", "us-east-1")
STAGE = os.environ.get("STAGE", STAGING)
STAGE_DASH_PREFIX = os.environ.get("STAGE_DASH_PREFIX", "stage-")
