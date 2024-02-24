import typer
from abstrakt.pythonModules.commandLine.layer_one.create import app as create_app
from abstrakt.pythonModules.commandLine.layer_one.delete import app as delete_app


class InfrastructureManager:
    def __init__(self):
        self.app = typer.Typer()
        self.app.add_typer(create_app, name="create", help='Create AWS/Azure/GCP Infrastructure',
                           rich_help_panel='Operations')
        self.app.add_typer(delete_app, name="delete", help='Delete AWS/Azure/GCP Infrastructure',
                           rich_help_panel='Operations')

    def run(self):
        self.app()
