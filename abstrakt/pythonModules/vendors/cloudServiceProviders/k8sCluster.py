from pydantic import BaseModel

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger


class ClusterBasicSetup(BaseModel):
  logger: CustomLogger
  config_file: str
  cluster_type: str
