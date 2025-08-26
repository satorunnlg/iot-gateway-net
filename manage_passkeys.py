#!/usr/bin/env python3
"""
Cognito パスキー管理スクリプト（完全版）

使用方法:
    python manage_passkeys.py list <region> <user-pool-id> <client-id> <username> [<identity-pool-id>]
    python manage_passkeys.py delete <region> <user-pool-id> <client-id> <username> <credential-id> [<identity-pool-id>]
    python manage_passkeys.py delete-all <region> <user-pool-id> <client-id> <username> [<identity-pool-id>]

必要なライブラリ:
    pip install boto3 colorama
"""

import argparse
import getpass
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from colorama import Fore, Style, init

# Coloramaを初期化（Windows対応）
init(autoreset=True)


class CognitoAuthenticator:
    """Cognito認証クラス"""
    
    def __init__(self, region: str):
        """初期化処理"""
        self.region = region
        try:
            self.cognito_idp = boto3.client('cognito-idp', region_name=region)
            self.cognito_identity = boto3.client('cognito-identity', region_name=region)
        except Exception as e:
            self._log_error(f"AWS Cognitoクライアントの初期化に失敗しました: {str(e)}")
            raise
    
    def _log_info(self, message: str) -> None:
        """情報ログを出力"""
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")
    
    def _log_error(self, message: str) -> None:
        """エラーログを出力"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}", file=sys.stderr)
    
    def _log_warn(self, message: str) -> None:
        """警告ログを出力"""
        print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {message}")
    
    def authenticate_user(self, user_pool_id: str, client_id: str, username: str) -> Optional[Dict]:
        """ユーザー認証を実行"""
        try:
            # パスワードを安全に取得
            password = getpass.getpass("パスワードを入力してください: ")
            
            self._log_info("ユーザー認証中...")
            
            # 初期認証を試行
            response = self.cognito_idp.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            
            # チャレンジが必要な場合の処理
            if 'ChallengeName' in response:
                return self._handle_auth_challenge(response, client_id, username)
            
            # 認証成功
            auth_result = response.get('AuthenticationResult', {})
            if auth_result:
                self._log_info("認証に成功しました。")
                return auth_result
            else:
                self._log_error("認証結果が取得できませんでした。")
                return None
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_messages = {
                'NotAuthorizedException': 'ユーザー名またはパスワードが正しくありません。',
                'UserNotConfirmedException': 'ユーザーが確認されていません。',
                'UserNotFoundException': 'ユーザーが見つかりません。',
                'TooManyRequestsException': 'リクエストが多すぎます。しばらく待ってから再試行してください。',
                'InvalidParameterException': 'パラメータが無効です。',
                'ResourceNotFoundException': 'ユーザープールまたはクライアントが見つかりません。'
            }
            
            user_message = error_messages.get(error_code, f"認証エラー: {e.response.get('Error', {}).get('Message', str(e))}")
            self._log_error(user_message)
            return None
            
        except Exception as e:
            self._log_error(f"予期しないエラーが発生しました: {str(e)}")
            return None
    
    def _handle_auth_challenge(self, response: Dict, client_id: str, username: str) -> Optional[Dict]:
        """認証チャレンジを処理"""
        challenge_name = response.get('ChallengeName')
        session = response.get('Session')
        
        if challenge_name == 'NEW_PASSWORD_REQUIRED':
            self._log_info("新しいパスワードの設定が必要です。")
            new_password = getpass.getpass("新しいパスワードを入力してください: ")
            
            try:
                challenge_response = self.cognito_idp.respond_to_auth_challenge(
                    ClientId=client_id,
                    ChallengeName=challenge_name,
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'NEW_PASSWORD': new_password
                    }
                )
                
                auth_result = challenge_response.get('AuthenticationResult', {})
                if auth_result:
                    self._log_info("パスワード更新と認証に成功しました。")
                    return auth_result
                    
            except ClientError as e:
                self._log_error(f"パスワード更新に失敗しました: {e.response.get('Error', {}).get('Message', str(e))}")
                return None
                
        elif challenge_name == 'MFA_SETUP':
            self._log_error("MFAセットアップが必要です。このスクリプトではMFAセットアップはサポートされていません。")
            return None
            
        elif challenge_name == 'SOFTWARE_TOKEN_MFA':
            totp_code = input("TOTP MFAコードを入力してください: ")
            
            try:
                challenge_response = self.cognito_idp.respond_to_auth_challenge(
                    ClientId=client_id,
                    ChallengeName=challenge_name,
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'SOFTWARE_TOKEN_MFA_CODE': totp_code
                    }
                )
                
                auth_result = challenge_response.get('AuthenticationResult', {})
                if auth_result:
                    self._log_info("MFA認証に成功しました。")
                    return auth_result
                    
            except ClientError as e:
                self._log_error(f"MFA認証に失敗しました: {e.response.get('Error', {}).get('Message', str(e))}")
                return None
                
        elif challenge_name == 'SMS_MFA':
            sms_code = input("SMS MFAコードを入力してください: ")
            
            try:
                challenge_response = self.cognito_idp.respond_to_auth_challenge(
                    ClientId=client_id,
                    ChallengeName=challenge_name,
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'SMS_MFA_CODE': sms_code
                    }
                )
                
                auth_result = challenge_response.get('AuthenticationResult', {})
                if auth_result:
                    self._log_info("SMS MFA認証に成功しました。")
                    return auth_result
                    
            except ClientError as e:
                self._log_error(f"SMS MFA認証に失敗しました: {e.response.get('Error', {}).get('Message', str(e))}")
                return None
        else:
            self._log_error(f"サポートされていない認証チャレンジです: {challenge_name}")
            return None
        
        return None
    
    def get_identity_credentials(self, identity_pool_id: str, id_token: str) -> Optional[Dict]:
        """Identity Poolから一時的なAWS認証情報を取得"""
        try:
            self._log_info("Identity Pool認証情報を取得中...")
            
            # Identity IDを取得
            identity_response = self.cognito_identity.get_id(
                IdentityPoolId=identity_pool_id,
                Logins={
                    f'cognito-idp.{self.region}.amazonaws.com/{identity_pool_id.split(":")[1]}': id_token
                }
            )
            
            identity_id = identity_response['IdentityId']
            
            # 一時的なAWS認証情報を取得
            credentials_response = self.cognito_identity.get_credentials_for_identity(
                IdentityId=identity_id,
                Logins={
                    f'cognito-idp.{self.region}.amazonaws.com/{identity_pool_id.split(":")[1]}': id_token
                }
            )
            
            return credentials_response.get('Credentials', {})
            
        except ClientError as e:
            self._log_error(f"Identity Pool認証情報の取得に失敗しました: {e.response.get('Error', {}).get('Message', str(e))}")
            return None
        except Exception as e:
            self._log_error(f"予期しないエラーが発生しました: {str(e)}")
            return None


class PasskeyManager:
    """Cognitoパスキー管理クラス"""
    
    def __init__(self, region: str, aws_credentials: Optional[Dict] = None):
        """初期化処理"""
        self.region = region
        
        try:
            if aws_credentials:
                # 一時的なAWS認証情報を使用
                self.cognito_client = boto3.client(
                    'cognito-idp',
                    region_name=region,
                    aws_access_key_id=aws_credentials['AccessKeyId'],
                    aws_secret_access_key=aws_credentials['SecretKey'],
                    aws_session_token=aws_credentials['SessionToken']
                )
            else:
                # デフォルトのAWS認証情報を使用
                self.cognito_client = boto3.client('cognito-idp', region_name=region)
                
        except Exception as e:
            self._log_error(f"AWS Cognitoクライアントの初期化に失敗しました: {str(e)}")
            raise
    
    def _log_info(self, message: str) -> None:
        """情報ログを出力"""
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")
    
    def _log_error(self, message: str) -> None:
        """エラーログを出力"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}", file=sys.stderr)
    
    def _log_warn(self, message: str) -> None:
        """警告ログを出力"""
        print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {message}")
    
    def _handle_cognito_error(self, error: ClientError, operation: str) -> None:
        """Cognitoエラーを処理"""
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        
        error_messages = {
            'NotAuthorizedException': 'アクセストークンが無効または期限切れです。',
            'UserNotFoundException': 'ユーザが見つかりません。',
            'ResourceNotFoundException': 'ユーザープールが見つかりません。',
            'InvalidParameterException': 'パラメータが無効です。',
            'TooManyRequestsException': 'リクエストが多すぎます。しばらく待ってから再試行してください。'
        }
        
        user_message = error_messages.get(error_code, f"予期しないエラーが発生しました: {error_message}")
        self._log_error(f"{operation}に失敗しました: {user_message}")
    
    def list_passkeys(self, user_pool_id: str, access_token: str) -> bool:
        """パスキー一覧を取得・表示"""
        self._log_info("パスキー一覧を取得中...")
        
        try:
            response = self.cognito_client.list_web_authn_credentials(
                AccessToken=access_token
            )
        except ClientError as e:
            self._handle_cognito_error(e, "パスキー一覧の取得")
            return False
        except Exception as e:
            self._log_error(f"予期しないエラーが発生しました: {str(e)}")
            return False
        
        credentials = response.get('Credentials', [])
        
        if not credentials:
            self._log_info("登録されているパスキーはありません。")
            return True
        
        self._log_info(f"登録されているパスキー ({len(credentials)} 件):")
        print()
        
        for i, credential in enumerate(credentials, 1):
            credential_id = credential.get('CredentialId', 'N/A')
            created_date = credential.get('CreatedDate')
            friendly_name = credential.get('FriendlyCredentialName', 'なし')
            
            # 日時を日本時間でフォーマット
            if created_date:
                try:
                    if isinstance(created_date, datetime):
                        formatted_date = created_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                    else:
                        formatted_date = str(created_date)
                except Exception:
                    formatted_date = str(created_date)
            else:
                formatted_date = 'N/A'
            
            print(f"{Fore.CYAN}[{i}] パスキー情報{Style.RESET_ALL}")
            print(f"    ID: {credential_id}")
            print(f"    作成日時: {formatted_date}")
            print(f"    説明: {friendly_name}")
            print("    " + "-" * 50)
        
        return True
    
    def delete_passkey(self, user_pool_id: str, access_token: str, credential_id: str) -> bool:
        """指定されたパスキーを削除"""
        self._log_info(f"パスキーを削除中: {credential_id}")
        
        try:
            self.cognito_client.delete_web_authn_credential(
                AccessToken=access_token,
                CredentialId=credential_id
            )
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                self._log_error(f"指定されたパスキーが見つかりません: {credential_id}")
            else:
                self._handle_cognito_error(e, "パスキーの削除")
            return False
        except Exception as e:
            self._log_error(f"予期しないエラーが発生しました: {str(e)}")
            return False
        
        self._log_info(f"パスキーを削除しました: {credential_id}")
        return True
    
    def delete_all_passkeys(self, user_pool_id: str, access_token: str) -> bool:
        """すべてのパスキーを削除"""
        self._log_info("全パスキー削除モード")
        
        # まず一覧を取得
        try:
            response = self.cognito_client.list_web_authn_credentials(
                AccessToken=access_token
            )
        except ClientError as e:
            self._handle_cognito_error(e, "パスキー一覧の取得")
            return False
        except Exception as e:
            self._log_error(f"予期しないエラーが発生しました: {str(e)}")
            return False
        
        credentials = response.get('Credentials', [])
        
        if not credentials:
            self._log_info("削除するパスキーはありません。")
            return True
        
        # 確認プロンプト
        self._log_warn(f"{len(credentials)} 件のパスキーが見つかりました。")
        print()
        for credential in credentials:
            credential_id = credential.get('CredentialId', 'N/A')
            friendly_name = credential.get('FriendlyCredentialName', '名前なし')
            print(f"- {credential_id} ({friendly_name})")
        
        print()
        try:
            confirmation = input("すべてのパスキーを削除しますか？ [y/N]: ").strip().lower()
        except KeyboardInterrupt:
            print()
            self._log_info("削除をキャンセルしました。")
            return True
        
        if confirmation not in ['y', 'yes']:
            self._log_info("削除をキャンセルしました。")
            return True
        
        # すべてのパスキーを削除
        success_count = 0
        error_count = 0
        
        for credential in credentials:
            credential_id = credential.get('CredentialId')
            if credential_id:
                if self.delete_passkey(user_pool_id, access_token, credential_id):
                    success_count += 1
                else:
                    error_count += 1
            else:
                self._log_error("無効なクレデンシャルIDが見つかりました。")
                error_count += 1
        
        self._log_info(f"削除完了: 成功 {success_count} 件, 失敗 {error_count} 件")
        
        return error_count == 0


def create_parser() -> argparse.ArgumentParser:
    """コマンドライン引数パーサーを作成"""
    parser = argparse.ArgumentParser(
        description="Cognito パスキー管理ツール（完全版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  %(prog)s list us-west-2 us-west-2_XXXXXXXXX 1234567890abcdef myuser
  %(prog)s delete us-west-2 us-west-2_XXXXXXXXX 1234567890abcdef myuser credential-id-here
  %(prog)s delete-all us-west-2 us-west-2_XXXXXXXXX 1234567890abcdef myuser

Identity Pool使用例:
  %(prog)s list us-west-2 us-west-2_XXXXXXXXX 1234567890abcdef myuser us-west-2:12345678-1234-1234-1234-123456789012

必要な環境:
  - Python パッケージ: boto3, colorama
  - AWS認証情報設定（Identity Pool使用時のみ）
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='実行するコマンド')
    
    # 共通引数
    base_args = [
        ('region', 'AWS リージョン (例: us-west-2)'),
        ('user_pool_id', 'Cognito ユーザープールID'),
        ('client_id', 'Cognito アプリクライアントID'),
        ('username', 'ログインするユーザー名')
    ]
    
    # listコマンド
    list_parser = subparsers.add_parser('list', help='パスキー一覧を表示')
    for arg, help_text in base_args:
        list_parser.add_argument(arg, help=help_text)
    list_parser.add_argument('identity_pool_id', nargs='?', help='Cognito アイデンティティプールID（オプション）')
    
    # deleteコマンド
    delete_parser = subparsers.add_parser('delete', help='指定されたパスキーを削除')
    for arg, help_text in base_args:
        delete_parser.add_argument(arg, help=help_text)
    delete_parser.add_argument('credential_id', help='削除するパスキーのクレデンシャルID')
    delete_parser.add_argument('identity_pool_id', nargs='?', help='Cognito アイデンティティプールID（オプション）')
    
    # delete-allコマンド
    delete_all_parser = subparsers.add_parser('delete-all', help='すべてのパスキーを削除')
    for arg, help_text in base_args:
        delete_all_parser.add_argument(arg, help=help_text)
    delete_all_parser.add_argument('identity_pool_id', nargs='?', help='Cognito アイデンティティプールID（オプション）')
    
    return parser


def check_dependencies() -> bool:
    """必要な依存関係をチェック"""
    missing_packages = []
    
    try:
        import boto3
    except ImportError:
        missing_packages.append('boto3')
    
    try:
        import colorama
    except ImportError:
        missing_packages.append('colorama')
    
    if missing_packages:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 必要なパッケージがインストールされていません:")
        for package in missing_packages:
            print(f"  - {package}")
        print(f"\n以下のコマンドでインストールしてください:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True


def main():
    """メイン処理"""
    # 依存関係チェック
    if not check_dependencies():
        sys.exit(1)
    
    # コマンドライン引数解析
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        # 認証処理
        authenticator = CognitoAuthenticator(args.region)
        auth_result = authenticator.authenticate_user(
            args.user_pool_id, 
            args.client_id, 
            args.username
        )
        
        if not auth_result:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 認証に失敗しました。")
            sys.exit(1)
        
        access_token = auth_result.get('AccessToken')
        if not access_token:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} アクセストークンが取得できませんでした。")
            sys.exit(1)
        
        # Identity Poolを使用する場合の処理
        aws_credentials = None
        if hasattr(args, 'identity_pool_id') and args.identity_pool_id:
            id_token = auth_result.get('IdToken')
            if id_token:
                aws_credentials = authenticator.get_identity_credentials(
                    args.identity_pool_id, 
                    id_token
                )
                if not aws_credentials:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Identity Pool認証情報の取得に失敗しました。")
                    sys.exit(1)
        
        # パスキーマネージャーを初期化
        manager = PasskeyManager(args.region, aws_credentials)
        
        # コマンド実行
        success = False
        
        if args.command == 'list':
            success = manager.list_passkeys(args.user_pool_id, access_token)
        elif args.command == 'delete':
            success = manager.delete_passkey(args.user_pool_id, access_token, args.credential_id)
        elif args.command == 'delete-all':
            success = manager.delete_all_passkeys(args.user_pool_id, access_token)
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print()
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} 処理がキャンセルされました。")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} 予期しないエラーが発生しました: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()