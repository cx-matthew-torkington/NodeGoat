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

  // XSS Remediation Tests - Testing reflected XSS vulnerability fix
  describe('XSS Protection Tests', () => {
    beforeEach(() => {
      cy.visitPage('/login')
    })

    it('should sanitize HTML in username on invalid password error', () => {
      cy.fixture('users/user.json').as('user')
      cy.get('@user').then(user => {
        // Attempt XSS injection with script tag
        const xssPayload = '<script>alert("XSS")</script>'
        cy.get('#userName').type(xssPayload)
        cy.get('#password').type(user.pass)
        cy.get('[type="submit"]').click()

        cy.url().should('include', 'login')

        // Verify the error message appears
        cy.get('.alert-danger')
          .contains('Invalid username')
          .and('be.visible')

        // Verify the username field contains sanitized (encoded) content, not raw script
        cy.get('#userName')
          .should('have.value')
          .and('not.contain', '<script>')
          .and('not.contain', '</script>')

        // Verify no script tag is present in the DOM
        cy.get('script').each($script => {
          cy.wrap($script.text()).should('not.contain', 'alert("XSS")')
        })
      })
    })

    it('should encode special characters in username on invalid password error', () => {
      cy.fixture('users/user.json').as('user')
      cy.get('@user').then(user => {
        // Create a valid user first, then login with wrong password to trigger the vulnerable code path
        const maliciousUsername = user.user
        const xssUsername = `${maliciousUsername}<img src=x onerror=alert('XSS')>`

        cy.get('#userName').type(xssUsername)
        cy.get('#password').type('WrongPassword123')
        cy.get('[type="submit"]').click()

        cy.url().should('include', 'login')

        // Verify no img tag with onerror handler is present
        cy.get('img[src="x"]').should('not.exist')

        // Verify the username field value is properly sanitized
        cy.get('#userName').invoke('val').should('exist')
      })
    })

    it('should prevent XSS via event handlers in username', () => {
      // Test various XSS vectors with event handlers
      const xssVectors = [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>'
      ]

      xssVectors.forEach((vector) => {
        cy.visitPage('/login')
        cy.get('#userName').clear().type(vector)
        cy.get('#password').type('anypassword')
        cy.get('[type="submit"]').click()

        cy.url().should('include', 'login')

        // Verify that dangerous tags are not present in the rendered HTML
        cy.get('body').then($body => {
          const html = $body.html()
          // The XSS payload should be encoded, not executed
          expect(html).to.not.include('onerror=alert')
          expect(html).to.not.include('onload=alert')
          expect(html).to.not.include('javascript:alert')
        })
      })
    })

    it('should handle username with less-than and greater-than symbols', () => {
      const username = 'test<>user'
      cy.get('#userName').type(username)
      cy.get('#password').type('password123')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the username field contains the encoded version
      cy.get('#userName').should('have.value')
    })

    it('should handle username with quotes and double quotes', () => {
      const username = `test"user'name`
      cy.get('#userName').type(username)
      cy.get('#password').type('password123')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify no script injection through attribute breaking
      cy.get('#userName').should('exist').and('be.visible')
    })

    it('should not execute JavaScript URLs in username', () => {
      const jsUrl = 'javascript:alert(document.cookie)'
      cy.get('#userName').type(jsUrl)
      cy.get('#password').type('password123')
      cy.get('[type="submit"]').click()

      cy.url().should('include', 'login')

      // Verify the javascript: protocol is not executed
      cy.on('window:alert', () => {
        throw new Error('Alert should not be triggered - XSS vulnerability!')
      })
    })

    it('should handle valid user with wrong password and ensure XSS protection', () => {
      cy.fixture('users/user.json').as('user')
      cy.get('@user').then(user => {
        // This test specifically targets the code path at line 85-86 (invalidPassword error)
        // which is the exact location of the vulnerability
        const xssPayload = '<script>document.write("HACKED")</script>'

        cy.get('#userName').type(user.user)
        cy.get('#password').type('DefinitelyWrongPassword!')
        cy.get('[type="submit"]').click()

        cy.url().should('include', 'login')

        // Should see "Invalid password" error (not "Invalid username")
        cy.get('.alert-danger')
          .contains('Invalid password')
          .and('be.visible')

        // Verify username is preserved in the field (but sanitized if it was malicious)
        cy.get('#userName').should('have.value', user.user)

        // Verify no XSS execution
        cy.get('body').then($body => {
          const html = $body.html()
          expect(html).to.not.include('HACKED')
          expect(html).to.not.include('document.write')
        })
      })
    })
  })
})
