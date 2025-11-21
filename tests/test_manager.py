import httpx

def test_oauth_flow(oauth_endpoint):
      response = httpx.post(
          f"{oauth_endpoint}/oauth2/token",
          data={"grant_type": "authorization_code", "code": "test"}
      )
      assert response.status_code == 200
