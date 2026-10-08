[idmefv2-connector]

param.idmefv2_endpoint = <string>
* IDMEFv2 endpoint the generated alert is sent to.

param.auth_type = none|bearer|basic
* Authentication mode used when sending to the endpoint. Default: none.

param.auth_token = <string>
* Bearer token used when auth_type=bearer.

param.auth_username = <string>
* Username used when auth_type=basic.

param.auth_password = <string>
* Password used when auth_type=basic.

param.verify_ssl = <boolean>
* Verifies the endpoint's TLS certificate. Disable only for lab/self-signed environments. Default: 1.

param.organisation_name = <string>
* IDMEFv2 OrganisationName value. Defaults to "CHANGE-ME" when not set.

param.organisation_id = <string>
* IDMEFv2 OrganisationId value. Defaults to "CHANGE-ME" when not set.
