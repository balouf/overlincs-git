module.exports = (grunt) ->

	grunt.registerTask 'user:test', "Create a test user with the given email address. Usage: grunt user:test --email=joe@example.com", () ->
		done = @async()
		email = grunt.option("email")
		if !email?
			console.error "Usage: grunt user:test --email=joe@example.com"
			process.exit(1)

		settings = require "settings-sharelatex"
		UserRegistrationHandler = require "../web/app/js/Features/User/UserRegistrationHandler"
		OneTimeTokenHandler = require "../web/app/js/Features/Security/OneTimeTokenHandler"
		UserRegistrationHandler.registerNewUser {
			email: email
			password: "TestTest42"
		}, (error, user) ->
			if error? and error?.message != "EmailAlreadyRegistered"
				throw error
			user.isAdmin = false
			user.confirmed = true
			user.save (error) ->
				throw error if error?
				ONE_WEEK = 7 * 24 * 60 * 60 # seconds
				OneTimeTokenHandler.getNewToken user._id, { expiresIn: ONE_WEEK }, (err, token)->
					return next(err) if err?

					console.log ""
					console.log """
						Successfully created and validated #{email} as an regular user.
					"""
					done()
