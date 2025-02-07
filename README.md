OIDC/oidc_userinfo PAM module
=================

This PAM module enables login with oidc_userinfo token instead of password.

NB : you must send "Bearer <token>" so that this module knows it really is not a plain password.

## How to install it:

```bash
$ sudo apt-get install libcurl4-openssl-dev libpam-dev
$ make
$ sudo make install
```

## Configuration

```
auth sufficient pam_oidc_userinfo.so <userinfo url> <login field> either_substring1 either_substring2
account sufficient pam_oidc_userinfo.so
```

## How it works

Lets assume that configuration is looking like:

```
auth sufficient pam_oidc_userinfo.so https://oidc.foo.org/userinfo sub "aud":["aud1"] "aud":["aud2"]
```

And somebody is trying to login with login=foo and token="Bearer bar".

pam_oidc_userinfo module will make http request with "Authorization: Bearer bar" and check response code and content.

If the response code is not 200 - authentication will fail. After that it will check response content:

It will check that response contains:  `"sub":"foo"` AND (`"aud":["aud1"]` or `"aud":["aud2"]`)

If it does not match, authentication will fail.

### Issues and Contributing

oidc_userinfo PAM module welcomes questions via our [issues tracker](https://github.com/CyberDem0n/pam-oidc_userinfo/issues). We also greatly appreciate fixes, feature requests, and updates; before submitting a pull request, please visit our [contributor guidelines](https://github.com/CyberDem0n/pam-oidc_userinfo/blob/master/CONTRIBUTING.rst).

License
-------

This project uses the [MIT license](https://github.com/CyberDem0n/pam-oidc_userinfo/blob/master/LICENSE).

## Testing with pamtester

```
% cat /etc/pam.d/test-oidc-userinfo 
auth required /home/prigaux/git/pam-oidc-userinfo/pam_oidc_userinfo.so https://oidc.foo.org/userinfo sub "aud":["aud1"]
```
```
access_token=ory_at_xxx-xxx-xxx.xxx-xxx-xxx
echo "Bearer $access_token" | pamtester -v test-oidc-userinfo prigaux authenticate
```

## Links

See also https://github.com/CSCfi/pam_userinfo (which does mostly the same thing, but a litle more complex and restrict to weird "login_aud")
