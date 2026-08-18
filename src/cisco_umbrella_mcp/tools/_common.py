from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No Cisco Umbrella credentials. Send the X-Umbrella-Api-Key and "
    "X-Umbrella-Key-Secret headers.",
    False,
)
