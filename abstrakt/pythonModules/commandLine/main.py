import typer
from abstrakt.pythonModules.commandLine.layer_one.create import app as create_app
from abstrakt.pythonModules.commandLine.layer_one.delete import app as delete_app
from abstrakt.pythonModules.commandLine.layer_one.install import install_sensor_app
from abstrakt.pythonModules.commandLine.layer_one.uninstall import uninstall_sensor_app


class InfrastructureManager:
    def __init__(self):
        self.app = typer.Typer()
        self.app.add_typer(create_app, name="create", help='Create AWS/Azure/GCP Infrastructure',
                           rich_help_panel='Operations')
        self.app.add_typer(delete_app, name="delete", help='Delete AWS/Azure/GCP Infrastructure',
                           rich_help_panel='Operations')
        self.app.add_typer(install_sensor_app, name="install", help='Install Runtime Agents and Sensors',
                           rich_help_panel='Operations')
        self.app.add_typer(uninstall_sensor_app, name="uninstall", help='Uninstall Runtime Agents and Sensors',
                           rich_help_panel='Operations')

    def run(self):
        self.app()
