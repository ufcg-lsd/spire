# Agent plugin: SVIDStore "sconecas_sessionmanager"

The `sconecas_sessionmanager` plugin stores in [SCONE CAS](https://sconedocs.github.io/CASOverview/) the resulting X509-SVIDs of the entries that the agent is entitled to. It is necessary to have an entry with the `-storeSVID` flag set.

The plugin uses session templates to give users more flexibility. Each template has placeholders used by the plugin to inject information and constraints for access control in the secret store.

> To learn more about CAS and LAS, how to use a public and deploy LAS locally, go to the [SCONE documentation](https://sconedocs.github.io/CASOverview/).

> :information_source: It's recommended to use [CAS namespaces](https://sconedocs.github.io/namespace/).

> :warning: The plugin can recover from most failure cases related to the session's predecessor management (ex., crashed agent, restarted CAS, CAS temporary unavailability). Despite this, when the plugin looses the local predecessor for an existing session in CAS, the plugin can not recover.


### Configuration

When the SVIDs are updated, the plugin takes care of creating (or updating) sessions into CAS. The sessions, created according the session templates described below, can have their secrets imported by the workloads' main sessions. Check the [policy language](https://sconedocs.github.io/CAS_session_lang_0_3/) out for more information.

| Configuration                           | Description |
| ----------------------------------------| ----------- |
| cas_connection_string                   |  CAS HTTPS connection string |
| cas_client_certificate                  |  Client certificate used to authorize the plugin |
| cas_client_key                          |  Client certificate key |
| trust_anchor_certificate                |  CAS identity certiticate: the plugin uses this certificate to ensure connections only with a known, attested CAS |
| insecure_skip_verify_tls                |  Skip TLS verification in connection with the configured CAS (**do not use in production**) |
| cas_predecessor_dir                     |  Data path where the plugin will keep predecessors of each session |
|            *                            |  **The next configurables define templates to be used along with placeholders to mint the desired sessions (the placeholders are presented in the next section)** |
| svid_session_template_file              |  Template file for sessions that carry the SVIDs and private keys |
| bundle_session_template_file            |  Template file for sessions that carry the trust bundles |
| federated_bundles_session_template_file |  Template file for sessions that carry federated bundles |

A sample configuration:

```
  SVIDStore "sconecas_sessionmanager" {
    plugin_data {
      cas_connection_string = "https://cas.scone:8081"
      cas_client_certificate = "/run/spire/config/cas-client.crt"
      cas_client_key = "/run/spire/config/cas-client.key"
      trust_anchor_certificate = "/run/spire/config/trust-anchor.crt"
      insecure_skip_verify_tls = false

      cas_predecessor_dir = "/run/spire"
      svid_session_template_file = "/run/spire/config/svid.template"
      bundle_session_template_file = "/run/spire/config/bundle.template"
      federated_bundles_session_template_file = "/run/spire/config/fed-bundles.template"
    }
  }
```


### Selectors

The selectors of the type `sconecas_sessionmanager` are used to describe the session that will import the SVID posted into the CAS by the `sconecas_sessionmanager` SVIDStore plugin.

| Selector                        | Example                                   | Description                                    |
| ------------------------------- | ----------------------------------------- | ---------------------------------------------- |
| `sconecas_sessionmanager:session_name` | `sconecas_sessionmanager:session_name:confidential-apps/mariadb-1` | Name of the session posted into SCONE CAS that will import the SVIDs |
| `sconecas_sessionmanager:session_hash`        | `sconecas_sessionmanager:session_hash:03aa3f5e2779b625a455651b54866447f995a2970d164581b4073044435359ed`         | HASH of the session returned by the SCONE CLI or CAS API  |
| `sconecas_sessionmanager:trust_bundle_session_name`   | `sconecas_sessionmanager:trust_bundle_session_name:spire-ca` | Name that replaces the `<\trust-bundle-session-name>` placeholder in the `bundle_session_template_file` |
| `sconecas_sessionmanager:fed_bundles_session_name` | `sconecas_sessionmanager:fed_bundles_session_name:fed-bundles` | Name that replaces the `<\fed-bundles-session-name>` placeholder in the `federated_bundles_session_template_file` |

sconecas_sessionmanager:session_hash

### Placeholders and Session Templates Examples

**Placeholders**

### Placeholders

The placeholders needed by the plugin for each session are:

|             Template file type            |         Placeholder        |                           Replaced with                           |
|:-----------------------------------------:|:--------------------------:|:-----------------------------------------------------------------:|
|         `svid_session_template_file`      |              *             |                                 *                                 |
|                     *                     |          `<\svid>`         |         SVID leaf certificate (PEM)         |
|                     *                     |          `<\svid-intermediates>`         |         SVID intermediate certificates (PEM)         |
|                     *                     |        `<\svid-key>`       |                           SVID key (PEM)                          |
|                     *                     | `<\session-name-selector>` | Value of the `session_name` selector (Name of the session that will import the SVID and the private key) |
|                     *                     | `<\session-hash-selector>` | Value of the `session_hash` selector (HASH of the session that will import the SVID and the private key) |
|                     *                     |      `<\predecessor>`      |                       Sessions' predecessors                      |
|       `bundle_session_template_file`      |              *             |                                 *                                 |
|                     *                     |      `<\trust-bundle-session-name>`     |      Value of the `trust_bundle_session_name` selector                    |
|                     *                     |      `<\trust-bundle>`     |                     Trust bundle for the SVIDs                    |
|                     *                     |      `<\predecessor>`      |                       Sessions' predecessors                      |
| `federated_bundles_session_template_file` |              *             |                                 *                                 |
|                     *                     |      `<\fed-bundles-session-name>`     |      Value of the `fed_bundles_session_name` selector                    |
|                                           |   `<\federated-bundles>`   |            Federated bundles associated with the SVIDs            |
|                     *                     |      `<\predecessor>`      |                       Sessions' predecessors                      |

**SVID session template examples** 

```yaml
name: spire-svid-<\session-name-selector>
version: "0.3"
predecessor: <\predecessor>
secrets:
  - name: svid
    kind: x509
    value: |
        <\svid>
    issuer: svid-intermediates
    export:
        session: <\session-name-selector>
        session_hash: <\session-hash-selector>
    private_key: svid_key
  - name: svid-intermediates
    kind: x509-ca
    value: |
        <\svid-intermediates>
    export:
        session: <\session-name-selector>
        session_hash: <\session-hash-selector>
  - name: svid_key
    kind: private-key
    value: |
        <\svid-key>
    export:
        session: <\session-name-selector>
        session_hash: <\session-hash-selector>
```

**Bundle session template**

```yaml
name: spire-ca-<\trust-bundle-session-name>
version: "0.3"
predecessor: <\predecessor>
secrets:
  - name: spire-ca
    kind: x509-ca
    export_public: true
    value: |
        <\trust-bundle>
```

**Federated bundles session template**

```yaml
name: spire-fed-bundles-<\fed-bundles-session-name>
version: "0.3"
predecessor: <\predecessor>
secrets:
  - name: spire-federated-bundles
    kind: x509-ca
    export_public: true
    value: |
        <\federated-bundles>
```
