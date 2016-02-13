package com.sample

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import com.bitbucket.thinbus.srp6.js.SRP6JavaClientSession
import com.bitbucket.thinbus.srp6.js.SRP6JavaClientSessionSHA256
import com.bitbucket.thinbus.srp6.js.HexHashedVerifierGenerator
import grails.plugin.springsecurity.SpringSecurityUtils

@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
class User implements Serializable {

	private static final long serialVersionUID = 1

	transient springSecurityService

	String username
	String password
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired
	String salt
	String verifier

	User(String username, String password) {
		this()
		this.username = username
		this.password = password
	}

	Set<Role> getAuthorities() {
		UserRole.findAllByUser(this)*.role
	}

	def beforeInsert() {
        srpUpdate() // Call SRP to update Salt and Verifier each time a user is created
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
            srpUpdate() // Call SRP to update Salt and Verifier each time password is changed
			encodePassword()
		}
	}

	protected void encodePassword() {
		password = springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(password) : password
	}

    protected void srpUpdate(){
        Map conf = SpringSecurityUtils.securityConfig
        // Create verifier generator
        String N = conf.srp.cryptoParams.N_base10
        String g = conf.srp.cryptoParams.g_base10
        String hashAlg = conf.srp.cryptoParams.hash
        SRP6JavaClientSession clientSession = new SRP6JavaClientSessionSHA256(N, g);
        HexHashedVerifierGenerator gen = new HexHashedVerifierGenerator(N,g,hashAlg);
        // Random 16 byte salt 's'
        String genSalt = clientSession.generateRandomSalt(16);
        // Compute verifier 'v'
        String genVerifier = gen.generateVerifier(genSalt, username, password);
        // Update salt and verifier fields
        salt = genSalt
        verifier = genVerifier
	}

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
        salt blank:true, nullable:true, maxSize:512
        verifier blank:true, nullable:true, maxSize:2050
	}

	static mapping = {
		password column: '`password`'
	}
}
