from octo.comdirect.auth import ComdirectAuth

if __name__ == "__main__":
    comdirect_auth = ComdirectAuth()
    comdirect_auth.oauth_flow()
