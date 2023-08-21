<?php
$wwa_default_mail_template = __('<p>Hi {%username%},</p>
<p>You have requested an one-time login link, please <a href="{%loginurl%}">click here</a> to login. The link can only be used once and expires in {%expiretime%} minute(s).</p>
<p>If the link above is not working, copy and paste this link into your browser: {%loginurl%}</p>
<p>If you have not requested a login link, please ignore this email.</p>
<p><a href="{%homeurl%}">{%sitename%}</a></p>', 'wp-webauthn');
?>
