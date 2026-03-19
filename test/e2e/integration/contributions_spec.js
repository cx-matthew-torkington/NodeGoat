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

  describe('Code Injection Attack Prevention', () => {
    it('Should reject code injection via eval expression in preTax', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection with eval
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type("eval('1+1')")

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type('5')

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('3')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message instead of success
      cy.get('.alert-error, .alert-danger')
        .should('be.visible')
        .should('contain', 'Invalid contribution percentages')

      cy.url().should('include', 'contributions')
    })

    it('Should reject code injection via require expression', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection with require
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type("require('fs')")

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type('5')

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('3')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message
      cy.get('.alert-error, .alert-danger')
        .should('be.visible')
        .should('contain', 'Invalid contribution percentages')

      cy.url().should('include', 'contributions')
    })

    it('Should reject code injection via Function constructor', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection with Function constructor
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type('10')

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type("Function('return 42')()")

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('3')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message
      cy.get('.alert-error, .alert-danger')
        .should('be.visible')
        .should('contain', 'Invalid contribution percentages')

      cy.url().should('include', 'contributions')
    })

    it('Should reject code injection via process.exit', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection with process.exit
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type('10')

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type('5')

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('process.exit(1)')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message
      cy.get('.alert-error, .alert-danger')
        .should('be.visible')
        .should('contain', 'Invalid contribution percentages')

      cy.url().should('include', 'contributions')
    })

    it('Should reject code injection with arithmetic expression and command', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection with complex expression
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type("1+1; console.log('hacked')")

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type('5')

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('3')

      cy.get('button[type="submit"]')
        .click()

      // Should show error message
      cy.get('.alert-error, .alert-danger')
        .should('be.visible')
        .should('contain', 'Invalid contribution percentages')

      cy.url().should('include', 'contributions')
    })

    it('Should accept only numeric values after fix', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Valid numeric input should work
      cy.get('table')
        .find('input')
        .eq(0)
        .clear()
        .type('10')

      cy.get('table')
        .find('input')
        .eq(1)
        .clear()
        .type('5')

      cy.get('table')
        .find('input')
        .eq(2)
        .clear()
        .type('3')

      cy.get('button[type="submit"]')
        .click()

      // Should show success message
      cy.get('.alert-success')
        .should('be.visible')

      cy.url().should('include', 'contributions')
    })
  })
})
