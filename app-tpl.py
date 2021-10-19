#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Cognito をバックエンドから利用するサーバーのサンプル
"""

import json
import hmac
import hashlib
import base64

import boto3
import requests
import jwt
from jwt.algorithms import RSAAlgorithm
from flask import (
    Flask, request, render_template, make_response, redirect
)

from typing import Optional


REGION = 'ap-northeast-1'
POOL_ID = '<input your cognito userpool id>'
APP_CLIENT_ID = '<input your app client id in cognito userpool>'
APP_CLIENT_SECRET = '<input your app client secret>'
PROFILE = '<input your local profile>'

COGNITO_URL = f'https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}'
jwks = requests.get(f'{COGNITO_URL}/.well-known/jwks.json').json()

session = boto3.session.Session(profile_name=PROFILE, region_name=REGION)
cognito = session.client('cognito-idp')

app = Flask(__name__)


def _secret_hash(username) -> str:
    # see - https://aws.amazon.com/jp/premiumsupport/knowledge-center/cognito-unable-to-verify-secret-hash/  # noqa
    message = bytes(username + APP_CLIENT_ID, 'utf-8')
    key = bytes(APP_CLIENT_SECRET, 'utf-8')
    digest = hmac.new(key, message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def _verify_token(cognito_userid: Optional[str],
                  id_token: Optional[str]) -> bool:
    """ Cognito User Pool の IdToken が有効か否かを返す """
    if not cognito_userid or not id_token:
        return False
    header = jwt.get_unverified_header(id_token)
    key_id = header['kid']
    alg = header['alg']
    keys = [k for k in jwks.get('keys', []) if k['kid'] == key_id]
    if len(keys) <= 0:
        return False
    public_key = RSAAlgorithm.from_jwk(json.dumps(keys[0]))

    try:
        payload = jwt.decode(
            id_token, public_key, algorithms=[alg], verify=True,
            options={'require_exp': True},
            audience=APP_CLIENT_ID, issuer=COGNITO_URL)
    except Exception:
        # 認証失敗 (エラーの種別を判断したいならここで処理)
        return False

    # sub クレームは、認証されたユーザーの固有識別子 (UUID)
    # ただし、UserPool の username と一致するとは限らない
    # そのため sub と cognito:username とも比較する
    return cognito_userid in [v for v in [
        payload.get('sub'), payload.get('cognito:username')
    ] if v]


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/create", methods=['GET', 'POST'])
def create():
    if request.method == 'GET':
        return render_template('createuser.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # ユーザー作成
            cognito.admin_create_user(
                UserPoolId=POOL_ID,
                Username=username,
                TemporaryPassword=password,
                MessageAction='SUPPRESS',   # RESEND にすればメールも送る
            )
        except Exception as err:
            # ログイン失敗時にはエラーが発生
            # 失敗時のデータを作るなどは実装時に工夫する
            raise err
        return render_template('createuser.html')


def _login(username, password) -> dict:
    """ サーバーから Cognito へ認証情報を受け渡す """
    try:
        return cognito.admin_initiate_auth(
            UserPoolId=POOL_ID, ClientId=APP_CLIENT_ID,
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': _secret_hash(username),
            }
        )
    except Exception as err:
        # ログイン失敗時にはエラーが発生
        # 失敗時のデータを作るなどは実装時に工夫する
        raise err


@app.post("/login")
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    res = _login(username, password)

    if res.get('ChallengeName') == 'NEW_PASSWORD_REQUIRED':
        # この場合、Cognito が新しいパスワードを要求している状態なので
        # 状況次第でパスワードリセット画面に飛ばすなどの実装を行う
        # ここでは、このステータスは無いものとして強制的にリセットする
        cognito.admin_set_user_password(
            UserPoolId=POOL_ID,
            Username=username, Password=password,
            Permanent=True)
        res = _login(username, password)

    # get cognito user id
    cognito_username = cognito.admin_get_user(
        UserPoolId=POOL_ID, Username=username)['Username']

    # トークンは取得できたが、クライアント側で直接利用する予定がなければ
    # サーバー側のキャッシュサーバーなどに保持して独自のセッションIDを発行しても良い
    response = make_response(render_template('login.html', **{
        'token': json.dumps(res, indent=2, ensure_ascii=False, default=str)
    }))

    # Cognito 検証のために必要な値を Cookie に設定して渡す
    response.set_cookie('username', value=cognito_username)
    response.set_cookie('id_token',
                        value=res['AuthenticationResult']['IdToken'])
    response.set_cookie('refresh_token',
                        value=res['AuthenticationResult']['RefreshToken'])
    return response


@app.post("/logout")
def logout():
    """ ログアウトを実施 """
    username = request.cookies.get('username')
    if username:
        try:
            cognito.adminUserGlobalSignOut(
                UserPoolId=POOL_ID, Username=username)
        except Exception:
            pass

    # Cookie をクリア
    response = make_response(redirect('/', code=302))
    response.delete_cookie('username')
    response.delete_cookie('id_token')
    response.delete_cookie('refresh_token')

    return response


@app.route("/refresh", methods=['GET', 'POST', 'PUT', 'DELETE'])
def refresh():
    """ 期限切れトークンのリフレッシュ """
    callback = request.args.get('callback')
    if not callback:
        raise ValueError('callback required')

    username = request.cookies.get('username')
    token = request.cookies.get('refresh_token')
    if not username or not token:
        # Cookie に入力がない場合 (ログインページなどに飛ばすのが良い)
        return redirect('/', code=302)

    try:
        # secret_hash で渡す username はログイン時はメールアドレスなどの
        # ログインが可能な情報でよかったが、リフレッシュの時は
        # Cognito UserPool 上で一意となる Username である必要がある
        res = cognito.admin_initiate_auth(
                UserPoolId=POOL_ID, ClientId=APP_CLIENT_ID,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': token,
                    'SECRET_HASH': _secret_hash(username)
                }
            )
    except Exception as err:
        # トークンの更新に失敗
        # ログイン期限が切れたと判断してログインページにリダイレクトするなど
        raise err

    # IDトークンを更新して callback を呼び出す
    response = make_response(redirect(callback, code=307))
    response.set_cookie('id_token',
                        value=res['AuthenticationResult']['IdToken'])

    return response


@app.get('/private/hello')
def private_hello():
    """ プライベートエリア """
    # バリデーション: 実際には decorator を作成して使うのが実践的
    username = request.cookies.get('username')
    id_token = request.cookies.get('id_token')
    if not _verify_token(username, id_token):
        return redirect('/refresh?callback=/private/hello', code=307)

    return render_template('private.html')


if __name__ == "__main__":
    app.run(debug=True, port=8000)
