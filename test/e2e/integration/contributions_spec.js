/// <reference types="Cypress" />

describe('/contributions behaviour', () => {
  before(() => {
    cy.dbReset()
  })

  afterEach(() => {
    cy.visitPage('/logout')
  })

  it('Should redirect if the user has not logged in', () => {
    cy.visitPage('/contributions')
    cy.url().should('include', 'login')
  })

  it('Should be accesible for a logged user', () => {
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.url().should('include', 'contributions')
  })

  it('Should be a table with several inputs', () => {
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.get('table')
      .find('input')
      .should('have.length', 3)
  })

  it('Should input be modified', () => {
    const value = '12'
    cy.userSignIn()
    cy.visitPage('/contributions')
    cy.get('table')
      .find('input')
      .first()
      .clear()
      .type(value)

    cy.get('button[type="submit"]')
      .click()

    cy.get('tbody > tr > td')
      .eq(1)
      .contains(`${value} %`)

    cy.get('.alert-success')
      .should('be.visible')

    cy.url().should('include', 'contributions')
  })

  describe('Security - Code Injection Prevention', () => {
    it('Should reject code injection attempts in preTax field', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection
      cy.get('input[name="preTax"]')
        .clear()
        .type('process.exit(1)')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message
      cy.get('.alert-danger')
        .should('be.visible')
        .and('contain', 'Invalid contribution percentages')
    })

    it('Should reject malicious payload attempting file system access', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type("require('fs').readFileSync('/etc/passwd')")

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      cy.get('.alert-danger')
        .should('be.visible')
        .and('contain', 'Invalid contribution percentages')
    })

    it('Should reject function invocation attempts', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('(() => 10)()')

      cy.get('button[type="submit"]')
        .click()

      cy.get('.alert-danger')
        .should('be.visible')
        .and('contain', 'Invalid contribution percentages')
    })

    it('Should accept valid numeric strings without executing them', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('10')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('8')

      cy.get('input[name="roth"]')
        .clear()
        .type('7')

      cy.get('button[type="submit"]')
        .click()

      cy.get('.alert-success')
        .should('be.visible')

      cy.get('tbody > tr > td')
        .eq(1)
        .contains('10 %')
    })

    it('Should reject expressions with arithmetic and code', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('10 + global.process.exit()')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      cy.get('.alert-danger')
        .should('be.visible')
        .and('contain', 'Invalid contribution percentages')
    })
  })
})
