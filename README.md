CAS SSO plugin for The Fascinator
====================

This project is a plugin for The Fascinator project: https://code.google.com/p/the-fascinator
though, typically, it would be used in an institutional build of ReDBox: http://code.google.com/p/redbox-mint/ .

[ANDS-funded development done as part of the Metadata Stores project.]

This plugin assumes that a CAS server has already been setup for use within the institution.

Note that CAS is only used for authentication (not authorisation), so you will need to configure a
roles plugin separately to assign roles to logged in users.

To compile the fascinator-authn-cas plugin:

	#> mvn install

To include the CAS plugin in your institutional build (when using ReDBox for example),
add the following dependency to your pom.xml:

		<dependency>
			<groupId>au.edu.adelaide.fascinator</groupId>
		    <artifactId>fascinator-authn-cas</artifactId>
		    <version>${cas.plugin.version}</version>
		</dependency>

You will need to add the unpack-cas-conf execution to the maven-dependency-plugin:

           <!-- 1st - Unpack Generic Mint setup -->
            <plugin>
                <artifactId>maven-dependency-plugin</artifactId>
                <version>2.1</version>
                <executions>
                    <execution>
			.
			.
			.
                    </execution>

					<!-- CAS Resources -->
					<execution>
						<id>unpack-cas-conf</id>
						<phase>process-resources</phase>
						<goals>
							<goal>unpack</goal>
						</goals>
						<configuration>
							<outputDirectory>${project.home}</outputDirectory>
							<artifactItems>
								<artifactItem>
								    <groupId>au.edu.adelaide.fascinator</groupId>
								    <artifactId>fascinator-authn-cas</artifactId>
									<classifier>redbox-config</classifier>
									<type>zip</type>
								</artifactItem>
							</artifactItems>
						</configuration>
					</execution>
                </executions>
            </plugin>

Configuration
====

In the sso section of home/config/system-config.json, enable the CAS plugin:

	.
	.
	.
	"sso": {
        	"plugins": ["CAS"],
	.
	.
	.

CAS
---

Add the CAS configuration section (at the top level of the JSON config):

    "CAS": {
        "casServerUrl": "https://cas.institution.edu.au/",
        "ssoLogout": true,
        "ticketValidatorClassName": "org.jasig.cas.client.validation.Cas20ServiceTicketValidator"
    }

### casServerUrl
The `casServerUrl` element defines the URL prefix for all CAS server requests. The CAS plugin will suffix
this URL with the appropriate CAS command (eg. validate) and parameters. This element is mandatory.

### ssoLogout
The `ssoLogout` element contains a boolean value that tells the CAS plugin whether it should notify the
CAS server when a user has logged out. This tells the CAS server that the user needs to supply their password
for the next CAS login. This element is optional. If omitted, this value defaults to false.
* Note that SSO logout functionality is not currently implemented as it requires a change to the PortalSecurityManager.

### ticketValidatorClassName
The `ticketValidatorClassName` element defines the fully qualified class name that should be used to
validate CAS tickets. This value will depend on the version of the CAS server. This element is optional.
If omitted, this value will default to "org.jasig.cas.client.validation.Cas10TicketValidator.Cas10TicketValidator".
