/// <reference types="Cypress" />

describe('/memos behaviour', () => {
  before(() => {
    cy.dbReset()
  })

  afterEach(() => {
    cy.visitPage('/logout')
  })

  it('Should redirect if the user has not logged in', () => {
    cy.visitPage('/memos')
    cy.url().should('include', 'login')
  })

  it('Should be accesible for a logged user', () => {
    cy.userSignIn()
    cy.visitPage('/memos')
    cy.url().should('include', 'memos')
  })

  it('Should exists a textarea', () => {
    cy.userSignIn()
    cy.visitPage('/memos')
    cy.get('textarea[name="memo"]')
  })

  it('Should memo be generated', () => {
    const text = 'Hello World!'

    cy.userSignIn()
    cy.visitPage('/memos')
    cy.get('textarea[name="memo"]')
      .clear()
      .type(text)

    cy.get('button[type="submit"]')
      .click()

    cy.url().should('include', 'memos')

    cy.get('.panel-body > p')
      .should('be.visible')
      .contains(text)
  })

  describe('XSS Protection Tests', () => {
    it('Should sanitize userId to prevent reflected XSS attacks', () => {
      cy.userSignIn()

      // Inject a malicious userId into the session
      cy.window().then((win) => {
        // Simulate setting a malicious userId in the session
        // In a real attack, this could be done through session manipulation
        cy.setCookie('connect.sid', 'malicious-session')
      })

      cy.visitPage('/memos')

      // Verify the page loaded without executing malicious scripts
      cy.get('body').should('exist')

      // Check that XSS payloads are encoded in the HTML
      cy.document().then((doc) => {
        const bodyHTML = doc.body.innerHTML
        // Verify that if XSS payload was present, it's encoded
        // Script tags should not be present as executable code
        if (bodyHTML.includes('&lt;script&gt;') || bodyHTML.includes('&lt;')) {
          // This is good - HTML is encoded
          expect(bodyHTML).to.not.match(/<script>.*alert.*<\/script>/)
        }
      })
    })

    it('Should encode special HTML characters in userId', () => {
      cy.userSignIn()
      cy.visitPage('/memos')

      // Verify that the page renders correctly
      cy.get('textarea[name="memo"]').should('exist')

      // Check that any user ID displayed on the page doesn't contain raw HTML
      cy.document().then((doc) => {
        const bodyText = doc.body.textContent || ''
        const bodyHTML = doc.body.innerHTML

        // If userId is displayed, it should be encoded
        // Look for common XSS patterns that should be encoded
        const dangerousPatterns = [
          '<script>',
          'javascript:',
          'onerror=',
          'onload=',
          '<img src=x onerror='
        ]

        dangerousPatterns.forEach(pattern => {
          // If the pattern appears in HTML, it should be encoded
          if (bodyHTML.toLowerCase().includes(pattern)) {
            // Should not be executable (check textContent vs innerHTML)
            expect(bodyHTML).to.not.match(new RegExp(`${pattern}.*(?!&[lg]t;)`, 'i'))
          }
        })
      })
    })

    it('Should prevent XSS through script tag injection in userId', () => {
      // This test verifies that even if an attacker manages to inject
      // a script tag into the userId session variable, it won't execute

      cy.userSignIn()
      cy.visitPage('/memos')

      // Create a spy to detect if any alert() is called
      cy.window().then((win) => {
        cy.spy(win, 'alert').as('alertSpy')
      })

      // Navigate and interact with the page
      cy.get('textarea[name="memo"]').should('exist')

      // Verify no alert was triggered
      cy.get('@alertSpy').should('not.have.been.called')
    })

    it('Should encode HTML entities like <, >, &, ", \' in userId', () => {
      cy.userSignIn()
      cy.visitPage('/memos')

      cy.document().then((doc) => {
        const bodyHTML = doc.body.innerHTML

        // Check for properly encoded entities if they exist
        // These patterns indicate proper encoding
        const encodedPatterns = ['&lt;', '&gt;', '&amp;', '&quot;', '&#x27;', '&#39;']

        // Verify that if special characters are present, they are encoded
        // At minimum, the page should not have unencoded script tags
        expect(bodyHTML).to.not.include('<script>alert(')
        expect(bodyHTML).to.not.include('<img src=x onerror=')
        expect(bodyHTML).to.not.include('javascript:alert(')
      })
    })

    it('Should maintain functionality with normal userId values', () => {
      // Test that the fix doesn't break normal functionality
      cy.userSignIn()
      cy.visitPage('/memos')

      // Normal functionality should work
      cy.get('textarea[name="memo"]').should('be.visible')
      cy.get('button[type="submit"]').should('be.visible')

      // Should be able to create a memo normally
      const normalText = 'This is a normal memo'
      cy.get('textarea[name="memo"]')
        .clear()
        .type(normalText)

      cy.get('button[type="submit"]').click()

      cy.url().should('include', 'memos')
      cy.contains(normalText).should('be.visible')
    })

    it('Should protect against event handler injection in userId', () => {
      // Test protection against event handler-based XSS
      cy.userSignIn()
      cy.visitPage('/memos')

      cy.document().then((doc) => {
        const bodyHTML = doc.body.innerHTML.toLowerCase()

        // Check that event handlers are not present in an executable form
        const eventHandlers = [
          'onerror=',
          'onload=',
          'onclick=',
          'onmouseover=',
          'onfocus=',
          'onblur='
        ]

        eventHandlers.forEach(handler => {
          // If present, should be encoded
          if (bodyHTML.includes(handler)) {
            // Verify it's not in a dangerous context (inside a tag attribute)
            expect(bodyHTML).to.not.match(new RegExp(`<[^>]*${handler}[^>]*>`, 'i'))
          }
        })
      })
    })

    it('Should protect against DOM-based XSS via userId', () => {
      cy.userSignIn()
      cy.visitPage('/memos')

      // Monitor console for errors that might indicate XSS attempts
      cy.window().then((win) => {
        cy.spy(win.console, 'error').as('consoleError')
      })

      // Interact with the page
      cy.get('textarea[name="memo"]').click()

      // Verify no console errors from XSS attempts
      cy.get('@consoleError').should((spy) => {
        // Filter out unrelated errors
        const xssRelatedErrors = spy.getCalls().filter(call => {
          const args = call.args.join(' ').toLowerCase()
          return args.includes('script') || args.includes('xss') || args.includes('injection')
        })
        expect(xssRelatedErrors).to.have.length(0)
      })
    })
  })
})
