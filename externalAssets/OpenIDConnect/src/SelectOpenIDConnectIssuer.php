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

class SelectOpenIDConnectIssuer extends UnlistedSpecialPage {

	public function __construct() {
		parent::__construct( 'SelectOpenIDConnectIssuer' );
	}

	/**
	 * @inheritDoc
	 */
	public function execute( $param ) {
		if ( isset( $GLOBALS['wgOpenIDConnect_Config'] ) &&
			isset( $_REQUEST['uri'] ) && isset( $_REQUEST['query'] ) ) {

			if ( isset( $_REQUEST['iss'] ) ) {
				$url = urldecode( $_REQUEST['uri'] );
				if ( strlen( $_REQUEST['query'] ) > 0 ) {
					$url .= "?" . urldecode( $_REQUEST['query'] );
				}
				if ( session_id() == '' ) {
					wfSetupSession();
				}
				$_SESSION['iss'] = $_REQUEST['iss'];
				$GLOBALS['wgOut']->redirect( $url );
			} else {

				$request = $this->getRequest();
				$this->setHeaders();

				$title =
					Title::newFromText( "Special:SelectOpenIDConnectIssuer" );
				$urlbase = $title->getFullURL();
				$urlbase .= "?uri=" . urlencode( $_REQUEST['uri'] );
				$urlbase .= "&query=" . urlencode( $_REQUEST['query'] );
				$urlbase .= "&iss=";

				$html = Html::openElement( 'div', [ 'style' => 'text-align:center' ] );
				$html .= Html::openElement( 'table' );
				$html .= Html::openElement( 'tr' );
				$GLOBALS['wgOut']->AddHtml( $html );

				foreach ( $GLOBALS['wgOpenIDConnect_Config'] as $iss => $data ) {
					$html = Html::openElement( 'td' );
					$html .= Html::openElement( 'table', [ 'style' => 'padding:20px;' ] );
					$html .= Html::openElement( 'tr' );
					if ( isset( $data['icon'] ) ) {
						$html .= Html::openElement( 'td',
							[ 'style' => 'text-align:center;' ] );
						$html .= Html::openElement( 'a', [ 'href' => $urlbase . $iss ] );
						$html .= Html::openElement( 'img', [ 'src' => $data['icon'] ] );
						$html .= Html::closeElement( 'img' );
						$html .= Html::closeElement( 'a' );
						$html .= Html::closeElement( 'td' );
						$html .= Html::closeElement( 'tr' );
						$html .= Html::openElement( 'tr' );
					}
					$html .= Html::openElement( 'td',
						[ 'style' => 'text-align:center;' ] );
					$html .= Html::openElement( 'a', [ 'href' => $urlbase . $iss ] );
					if ( isset( $data['name'] ) ) {
						$html .= $data['name'];
					} else {
						$html .= $iss;
					}
					$html .= Html::closeElement( 'a' );
					$html .= Html::closeElement( 'td' );
					$html .= Html::closeElement( 'tr' );
					$html .= Html::closeElement( 'table' );
					$html .= Html::closeElement( 'td' );
					$GLOBALS['wgOut']->AddHtml( $html );
				}

				$html = Html::closeElement( 'tr' );
				$html .= Html::closeElement( 'table' );
				$html .= Html::closeElement( 'div' );
				$GLOBALS['wgOut']->AddHtml( $html );
			}
		}
	}
}
