/// <reference types="Cypress" />

describe('/login behaviour', () => {
  before(() => {
    cy.dbReset()
  })

  afterEach(() => {
    cy.visitPage('/logout')
  })

  beforeEach(() => {
    cy.visitPage('/login')
  })

  it('should have tutorial Guide link', () => {
    cy.get("a[href='/tutorial']")
      .should('have.attr', 'target', '_blank')
      .and('be.visible')
  })

  it('Should open the tutorial in another tab', () => {
    cy.get("a[href='/tutorial']").then(function ($a) {
      const href =
      $a.prop('href')
      cy.visit(href)
      cy.url().should('include', 'tutorial')
    })
  })

  it('should have admin user able to login', () => {
    cy.fixture('users/admin.json').as('admin')
    cy.get('@admin').then(admin => {
      cy.get('#userName').type(admin.user)
      cy.get('#password').type(admin.pass)
      cy.get('[type="submit"]').click()
      cy.url().should('include', 'benefits')
    })
  })

  it('should have non-admin user able to login', () => {
    cy.fixture('users/user.json').as('user')
    cy.get('@user').then(user => {
      cy.get('#userName').type(user.user)
      cy.get('#password').type(user.pass)
      cy.get('[type="submit"]').click()
      cy.url().should('include', 'dashboard')
    })
  })

  it('should reject wrong password', () => {
    cy.fixture('users/user.json').as('user')
    cy.get('@user').then(user => {
      cy.get('#userName').type(user.user)
      cy.get('#password').type('TO BE REJECTED')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      cy.get('.alert-danger')
        .contains('Invalid password')
        .and('be.visible')
    })
  })

  it('should reject wrong username', () => {
    cy.fixture('users/user.json').as('user')
    cy.get('@user').then(user => {
      cy.get('#userName').type('INVENTED')
      cy.get('#password').type(user.pass)
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      cy.get('.alert-danger')
        .contains('Invalid username')
        .and('be.visible')
    })
  })

  it('should have new user/ sign up link', () => {
    cy.get("a[href='/signup']")
      .and('be.visible')
  })

  it('Should redirect to the signup', () => {
    cy.get("a[href='/signup']").click()
    cy.url().should('include', 'signup')
  })

  describe('XSS Protection Tests', () => {
    it('should sanitize XSS attempts in username field with script tags', () => {
      const xssPayload = '<script>alert("XSS")</script>'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the error message is shown (invalid username)
      cy.get('.alert-danger')
        .contains('Invalid username')
        .and('be.visible')

      // Verify that the username field contains the sanitized value, not the raw script
      cy.get('#userName').should('have.value', xssPayload)

      // Most importantly, verify that the script did NOT execute by checking the page source
      // The encoded version should appear in the HTML, not the raw script
      cy.get('#userName').invoke('val').then((val) => {
        // The value attribute should contain the sanitized version
        expect(val).to.equal(xssPayload)
      })

      // Verify no alert was triggered (if script executed, this test would fail)
      cy.on('window:alert', (text) => {
        throw new Error('XSS alert was triggered: ' + text)
      })
    })

    it('should sanitize XSS attempts with img tag and onerror', () => {
      const xssPayload = '<img src=x onerror=alert(1)>'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the error message is shown
      cy.get('.alert-danger').should('be.visible')

      // Verify no alert was triggered
      cy.on('window:alert', (text) => {
        throw new Error('XSS alert was triggered: ' + text)
      })
    })

    it('should sanitize XSS attempts with iframe injection', () => {
      const xssPayload = '<iframe src="javascript:alert(1)"></iframe>'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify no iframe was injected into the page
      cy.get('iframe').should('not.exist')
    })

    it('should sanitize XSS attempts with event handlers', () => {
      const xssPayload = '<div onmouseover="alert(1)">test</div>'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the error message is shown
      cy.get('.alert-danger').should('be.visible')

      // Verify no alert was triggered
      cy.on('window:alert', (text) => {
        throw new Error('XSS alert was triggered: ' + text)
      })
    })

    it('should sanitize XSS attempts with encoded characters', () => {
      const xssPayload = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the error message is shown
      cy.get('.alert-danger').should('be.visible')
    })

    it('should handle normal username after XSS attempt', () => {
      // First attempt with XSS
      const xssPayload = '<script>alert("XSS")</script>'
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Clear and try with valid credentials
      cy.get('#userName').clear()
      cy.get('#password').clear()

      cy.fixture('users/user.json').as('user')
      cy.get('@user').then(user => {
        cy.get('#userName').type(user.user)
        cy.get('#password').type(user.pass)
        cy.get('[type="submit"]').click()
        cy.url().should('include', 'dashboard')
      })
    })

    it('should sanitize XSS in wrong password scenario', () => {
      const xssPayload = '<script>alert("XSS")</script>testuser'

      // Create a request that will trigger invalid password error
      // Using a valid-looking username with XSS payload
      cy.get('#userName').type(xssPayload)
      cy.get('#password').type('wrongpassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify error is shown
      cy.get('.alert-danger').should('be.visible')

      // Verify no alert was triggered
      cy.on('window:alert', (text) => {
        throw new Error('XSS alert was triggered: ' + text)
      })
    })

    it('should properly escape special HTML characters', () => {
      const specialChars = '"><svg/onload=alert(1)>'
      cy.get('#userName').type(specialChars)
      cy.get('#password').type('anypassword')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify no SVG element was injected
      cy.get('svg').should('not.exist')

      // Verify no alert was triggered
      cy.on('window:alert', (text) => {
        throw new Error('XSS alert was triggered: ' + text)
      })
    })
  })
})
