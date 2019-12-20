<?php

/*
 * Copyright (c) 2015-2018 The MITRE Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

use \MediaWiki\Session\SessionManager;
use \MediaWiki\Auth\AuthManager;
use \Jumbojett\OpenIDConnectClient;

class OpenIDConnect extends PluggableAuth {

	private $subject;
	private $issuer;

	const OIDC_SUBJECT_SESSION_KEY = 'OpenIDConnectSubject';
	const OIDC_ISSUER_SESSION_KEY = 'OpenIDConnectIssuer';

	/**
	 * @since 1.0
	 *
	 * @param int &$id
	 * @param string &$username
	 * @param string &$realname
	 * @param string &$email
	 * @param string &$errorMessage
	 * @return bool true if user is authenticated, false otherwise
	 */
	public function authenticate( &$id, &$username, &$realname, &$email,
		&$errorMessage ) {
		if ( !array_key_exists( 'SERVER_PORT', $_SERVER ) ) {
			wfDebugLog( 'OpenID Connect', 'in authenticate, server port not set' .
				PHP_EOL );
			return false;
		}

		if ( !isset( $GLOBALS['wgOpenIDConnect_Config'] ) ) {
			wfDebugLog( 'OpenID Connect', 'wgOpenIDConnect_Config not set' .
				PHP_EOL );
			return false;
		}

		try {

			$session = SessionManager::getGlobalSession();

			$iss = $session->get( 'iss' );

			if ( !is_null( $iss ) ) {

				if ( isset( $_REQUEST['code'] ) && isset( $_REQUEST['status'] ) ) {
					$session->remove( 'iss' );
				}

				if ( isset( $GLOBALS['wgOpenIDConnect_Config'][$iss] ) ) {

					$config = $GLOBALS['wgOpenIDConnect_Config'][$iss];

					if ( !isset( $config['clientID'] ) ||
						!isset( $config['clientsecret'] ) ) {
						wfDebugLog( 'OpenID Connect',
							'OpenID Connect: clientID or clientsecret not set for ' . $iss .
							'.' . PHP_EOL );
						$params = [
							'uri' => urlencode( $_SERVER['REQUEST_URI'] ),
							'query' => urlencode( $_SERVER['QUERY_STRING'] )
						];
						self::redirect( 'Special:SelectOpenIDConnectIssuer',
							$params, true );
						return false;
					}

				} else {
					wfDebugLog( 'OpenID Connect', 'Issuer ' . $iss .
						' does not exist in wgOpeIDConnect_Config.' . PHP_EOL );
					return false;
				}

			} else {

				$iss_count = count( $GLOBALS['wgOpenIDConnect_Config'] );

				if ( $iss_count < 1 ) {
					return false;
				}

				if ( $iss_count == 1 ) {

					$iss = array_keys( $GLOBALS['wgOpenIDConnect_Config'] );
					$iss = $iss[0];

					$values = array_values( $GLOBALS['wgOpenIDConnect_Config'] );
					$config = $values[0];

					if ( !isset( $config['clientID'] ) ||
						!isset( $config['clientsecret'] ) ) {
						wfDebugLog( 'OpenID Connect',
							'OpenID Connect: clientID or clientsecret not set for ' .
							$iss . '.' . PHP_EOL );
						return false;
					}

				} else {

					$params = [
						'uri' => urlencode( $_SERVER['REQUEST_URI'] ),
						'query' => urlencode( $_SERVER['QUERY_STRING'] )
					];
					self::redirect( 'Special:SelectOpenIDConnectIssuer',
						$params, true );
					return false;
				}
			}

			$clientID = $config['clientID'];
			$clientsecret = $config['clientsecret'];
			
			$oidc = new OpenIDConnectClient( $iss, $clientID, $clientsecret );

			//for modern openid providers the user information is inside the token id
			if ( isset($config['userInfoFromToken']) ) {
				$oidc->setIsUserInfoToken($config['userInfoFromToken']);
			}

			if ( isset( $_REQUEST['forcelogin'] ) ) {
				$oidc->addAuthParam( [ 'prompt' => 'login' ] );
			}
			if ( isset( $config['authparam'] ) &&
				is_array( $config['authparam'] ) ) {
				$oidc->addAuthParam( $config['authparam'] );
			}
			if ( isset( $config['scope'] ) ) {
				$scope = $config['scope'];
				if ( is_array( $scope ) ) {
					foreach ( $scope as $s ) {
						$oidc->addScope( $s );
					}
				} else {
					$oidc->addScope( $scope );
				}
			}
			if ( isset( $config['proxy'] ) ) {
				$oidc->setHttpProxy( $config['proxy'] );
			}
			$redirectURL =
				SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL();
			$oidc->setRedirectURL( $redirectURL );
			wfDebugLog( 'OpenID Connect', 'Redirect URL: ' . $redirectURL );
			if ( $oidc->authenticate() ) {

				$realname = $oidc->requestUserInfo( 'name' );
				$email = $oidc->requestUserInfo( 'email' );
				$this->subject = $oidc->requestUserInfo( 'sub' );
				$this->issuer = $oidc->getProviderURL();
				wfDebugLog( 'OpenID Connect', 'Real name: ' . $realname .
					', Email: ' . $email . ', Subject: ' . $this->subject .
					', Issuer: ' . $this->issuer );

				list( $id, $username ) =
					$this->findUser( $this->subject, $this->issuer );
				if ( !is_null( $id ) ) {
					wfDebugLog( 'OpenID Connect',
						'Found user with matching subject and issuer.' . PHP_EOL );
					return true;
				}

				wfDebugLog( 'OpenID Connect',
					'No user found with matching subject and issuer.' . PHP_EOL );

				if ( $GLOBALS['wgOpenIDConnect_MigrateUsersByEmail'] === true ) {
					wfDebugLog( 'OpenID Connect', 'Checking for email migration.' .
						PHP_EOL );
					list( $id, $username ) = $this->getMigratedIdByEmail( $email );
					if ( !is_null( $id ) ) {
						$this->saveExtraAttributes( $id );
						wfDebugLog( 'OpenID Connect', 'Migrated user ' . $username .
							' by email: ' . $email . '.' . PHP_EOL );
						return true;
					}
				}

				$preferred_username = $this->getPreferredUsername( $config, $oidc,
					$realname, $email );
				wfDebugLog( 'OpenID Connect', 'Preferred username: ' .
					$preferred_username . PHP_EOL );

				if ( $GLOBALS['wgOpenIDConnect_MigrateUsersByUserName'] === true ) {
					wfDebugLog( 'OpenID Connect', 'Checking for username migration.' .
						PHP_EOL );
					$id = $this->getMigratedIdByUserName( $preferred_username );
					if ( !is_null( $id ) ) {
						$this->saveExtraAttributes( $id );
						wfDebugLog( 'OpenID Connect', 'Migrated user by username: ' .
							$preferred_username . '.' . PHP_EOL );
						$username = $preferred_username;
						return true;
					}
				}

				$username = self::getAvailableUsername( $preferred_username,
					$realname, $email );

				wfDebugLog( 'OpenID Connect', 'Available username: ' .
					$username . PHP_EOL );

				$authManager = Authmanager::singleton();
				$authManager->setAuthenticationSessionData(
					self::OIDC_SUBJECT_SESSION_KEY, $this->subject );
				$authManager->setAuthenticationSessionData(
					self::OIDC_ISSUER_SESSION_KEY, $this->issuer );
				return true;
			}

		} catch ( Exception $e ) {
			wfDebugLog( 'OpenID Connect', $e->__toString() . PHP_EOL );
			$errorMessage = $e->__toString();
			$session->clear();
			return false;
		}
	}

	/**
	 * @since 1.0
	 *
	 * @param User &$user
	 */
	public function deauthenticate( User &$user ) {
		if ( $GLOBALS['wgOpenIDConnect_ForceLogout'] === true ) {
			$returnto = 'Special:UserLogin';
			$params = [ 'forcelogin' => 'true' ];
			self::redirect( $returnto, $params );
		}
	}

	/**
	 * @since 1.0
	 *
	 * @param int $id user id
	 */
	public function saveExtraAttributes( $id ) {
		$authManager = Authmanager::singleton();
		if ( is_null( $this->subject ) ) {
			$this->subject = $authManager->getAuthenticationSessionData(
				self::OIDC_SUBJECT_SESSION_KEY );
			$authManager->removeAuthenticationSessionData(
				self::OIDC_SUBJECT_SESSION_KEY );
		}
		if ( is_null( $this->issuer ) ) {
			$this->issuer = $authManager->getAuthenticationSessionData(
				self::OIDC_ISSUER_SESSION_KEY );
			$authManager->removeAuthenticationSessionData(
				self::OIDC_ISSUER_SESSION_KEY );
		}
		$dbw = wfGetDB( DB_MASTER );
		$dbw->upsert(
			'openid_connect',
			[
				'oidc_user' => $id,
				'oidc_subject' => $this->subject,
				'oidc_issuer' => $this->issuer
			],
			[
				[ 'oidc_user' ]
			],
			[
				'oidc_subject' => $this->subject,
				'oidc_issuer' => $this->issuer
			],
			__METHOD__
		);
	}

	private static function findUser( $subject, $issuer ) {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id',
				'user_name'
			],
			[
				'oidc_subject' => $subject,
				'oidc_issuer' => $issuer
			],
			__METHOD__,
			[],
			[
				'openid_connect' => [ 'JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row === false ) {
			return [ null, null ];
		} else {
			return [ $row->user_id, $row->user_name ];
		}
	}

	private static function getPreferredUsername( $config, $oidc, $realname,
		$email ) {
		if ( isset( $config['preferred_username'] ) ) {
			wfDebugLog( 'OpenID Connect', 'Using ' . $config['preferred_username'] .
				' attribute for preferred username.' . PHP_EOL );
			$preferred_username =
				$oidc->requestUserInfo( $config['preferred_username'] );
		} else {
			$preferred_username = $oidc->requestUserInfo( 'preferred_username' );
		}
		if ( strlen( $preferred_username ) > 0 ) {
			$preferred_username = $preferred_username;
		} elseif ( strlen( $realname ) > 0 &&
			$GLOBALS['wgOpenIDConnect_UseRealNameAsUserName'] === true ) {
			$preferred_username = $realname;
		} elseif ( strlen( $email ) > 0 &&
			$GLOBALS['wgOpenIDConnect_UseEmailNameAsUserName'] === true ) {
			$pos = strpos( $email, '@' );
			if ( $pos !== false && $pos > 0 ) {
				$preferred_username = substr( $email, 0, $pos );
			} else {
				$preferred_username = $email;
			}
		} else {
			return null;
		}
		$nt = Title::makeTitleSafe( NS_USER, $preferred_username );
		if ( is_null( $nt ) ) {
			return null;
		}
		return $preferred_username;
	}

	private static function getMigratedIdByUserName( $username ) {
		$nt = Title::makeTitleSafe( NS_USER, $username );
		if ( is_null( $nt ) ) {
			wfDebugLog( 'OpenID Connect',
				'Invalid preferred username for migration: ' . $username . '.' .
				PHP_EOL );
			return null;
		}
		$username = $nt->getText();
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id'
			],
			[
				'user_name' => $username,
				'oidc_user' => null
			],
			__METHOD__,
			[],
			[
				'openid_connect' => [ 'LEFT JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row !== false ) {
			return $row->user_id;
		}
		return null;
	}

	private static function getMigratedIdByEmail( $email ) {
		wfDebugLog( 'OpenID Connect', 'Matching user to email ' . $email . '.' .
			PHP_EOL );
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id',
				'user_name',
				'oidc_user'
			],
			[
				'user_email' => $email
			],
			__METHOD__,
			[
				// if multiple matching accounts, use the oldest one
				'ORDER BY' => 'user_registration'
			],
			[
				'openid_connect' => [ 'LEFT JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row !== false && $row->oidc_user === null ) {
			return [ $row->user_id, $row->user_name ];
		}
		return [ null, null ];
	}

	private static function getAvailableUsername( $preferred_username ) {
		if ( is_null( $preferred_username ) ) {
			$preferred_username = 'User';
		}

		if ( is_null( User::idFromName( $preferred_username ) ) ) {
			return $preferred_username;
		}

		$count = 1;
		while ( !is_null( User::idFromName( $preferred_username . $count ) ) ) {
			$count++;
		}
		return $preferred_username . $count;
	}

	private static function redirect( $page, $params = [], $doExit = false ) {
		$title = Title::newFromText( $page );
		if ( is_null( $title ) ) {
			$title = Title::newMainPage();
		}
		$url = $title->getFullURL( $params );
		header( 'Location: ' . $url );
		if ( $doExit ) {
			exit;
		}
	}

	/**
	 * Implements LoadExtensionSchemaUpdates hook.
	 *
	 * @param DatabaseUpdater $updater
	 */
	public static function loadExtensionSchemaUpdates( $updater ) {
		$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
		$type = $updater->getDB()->getType();
		$updater->addExtensionTable( 'openid_connect',
			$dir . $type . '/AddTable.sql' );
		$updater->addExtensionUpdate( [ [ __CLASS__, 'migrateSubjectAndIssuer' ],
			$updater ] );
	}

	/**
	 * Migrate subject and issuer columns from user table to openid_connect
	 * table.
	 *
	 * @param DatabaseUpdater $updater
	 */
	public static function migrateSubjectAndIssuer( $updater ) {
		if ( $updater->getDB()->fieldExists( 'user', 'subject', __METHOD__ ) &&
			$updater->getDB()->fieldExists( 'user', 'issuer', __METHOD__ ) ) {
			$maintenance = new FakeMaintenance();
			$task = $maintenance->runChild(
				'MigrateOIDCSubjectAndIssuerFromUserTable' );
			if ( $task->execute() ) {
				$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
				$type = $updater->getDB()->getType();
				$patch = $dir . $type . '/DropColumnsFromUserTable.sql';
				$updater->modifyField( 'user', 'subject', $patch, true );
			}
		} else {
			$updater->output(
				'...user table does not have subject and issuer columns.' . PHP_EOL );
		}
	}
}
