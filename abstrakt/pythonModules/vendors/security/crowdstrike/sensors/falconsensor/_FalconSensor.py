from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._CrowdStrikeSensors import CrowdStrikeSensors


class FalconSensor(CrowdStrikeSensors):
  sensor_image_tag: str
  sensor_tags: str
