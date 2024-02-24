import typer

from abstrakt.pythonModules.commandLine.layer_one.layer_two.deleteAWS import delete_aws_app
from abstrakt.pythonModules.commandLine.layer_one.layer_two.deleteAzure import delete_azure_app
from abstrakt.pythonModules.commandLine.layer_one.layer_two.deleteGCP import delete_gcp_app

# Create a Typer application
app = typer.Typer()

# Add subcommands for creating infrastructure on different cloud providers
app.add_typer(delete_aws_app, name="aws", help='Delete AWS Infrastructure',
              rich_help_panel="Public Cloud Providers")
app.add_typer(delete_azure_app, name="azure", help='Delete Azure Infrastructure',
              rich_help_panel="Public Cloud Providers")
app.add_typer(delete_gcp_app, name="gcp", help='Delete GCP Infrastructure',
              rich_help_panel="Public Cloud Providers")
