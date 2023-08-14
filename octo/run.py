from octo.comdirect.auth import ComdirectAuth

if __name__ == "__main__":
    comdirect_auth = ComdirectAuth(tan_wait_time=20)
    # comdirect_auth.oauth_flow()
    token = comdirect_auth.auth_resource_owner_password_flow()
    comdirect_auth.cd_secondary_flow(token.access_token)
