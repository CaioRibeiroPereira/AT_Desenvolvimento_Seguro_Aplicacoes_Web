SENHAS = {
    "admin": "senha-admin-teste",
    "dr_silva": "senha-silva-teste",
    "dr_souza": "senha-souza-teste",
    "recepcao": "senha-recep-teste",
}
MFA = "654321"
LAB_CLIENT_ID = "lab-teste"
LAB_CLIENT_SECRET = "segredo-lab-teste"


def auth_header(client, username: str) -> dict:
    data = {"username": username, "password": SENHAS[username]}
    if username == "admin":
        data["mfa_code"] = MFA
    resposta = client.post("/auth/login", data=data)
    assert resposta.status_code == 200, resposta.text
    return {"Authorization": f"Bearer {resposta.json()['access_token']}"}


def lab_auth_header(client, client_secret: str = LAB_CLIENT_SECRET) -> dict:
    resposta = client.post(
        "/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": LAB_CLIENT_ID,
            "client_secret": client_secret,
        },
    )
    assert resposta.status_code == 200, resposta.text
    return {"Authorization": f"Bearer {resposta.json()['access_token']}"}
