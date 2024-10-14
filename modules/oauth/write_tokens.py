import json
from datetime import datetime, timezone

def write_tokens_to_file(tokens):
    token_data = {
        "access_token_issued": datetime.now(timezone.utc).isoformat(),
        "refresh_token_issued": datetime.now(timezone.utc).isoformat(),
        "token_dictionary": tokens
    }
    with open('tokens.json', 'w') as f:
        json.dump(token_data, f, indent=4)
