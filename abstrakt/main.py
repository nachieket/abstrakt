import sys
from abstrakt.pythonModules.commandLine.main import InfrastructureManager


def app():
    try:
        manager = InfrastructureManager()
        manager.run()
    except Exception as e:
        print(f"An error occurred in the main application: {e}", file=sys.stderr)
        raise  # Re-raise the exception after logging it


if __name__ == "__main__":
    app()

# Na dil hai... Bura... Na hum hai... Bure...
# Yeh duniya... Buri To hum kya kare...
# Usiki sikhai... Usi ko sikhaye...
# Thoda sa kar le Dhamal...
