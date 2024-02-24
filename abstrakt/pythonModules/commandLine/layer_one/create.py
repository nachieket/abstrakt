import typer

from abstrakt.pythonModules.commandLine.layer_one.layer_two.createAWS import create_aws_app
from abstrakt.pythonModules.commandLine.layer_one.layer_two.createAzure import create_azure_app
from abstrakt.pythonModules.commandLine.layer_one.layer_two.createGCP import create_gke_app

# Create a Typer application
app = typer.Typer()

# Add subcommands for creating infrastructure on different cloud providers
app.add_typer(create_aws_app, name="aws", help='Create AWS Infrastructure',
              rich_help_panel="Public Cloud Providers")
app.add_typer(create_azure_app, name="azure", help='Create Azure Infrastructure',
              rich_help_panel="Public Cloud Providers")
app.add_typer(create_gke_app, name="gcp", help='Create GCP Infrastructure',
              rich_help_panel="Public Cloud Providers")
