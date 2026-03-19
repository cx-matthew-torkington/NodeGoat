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

  // Security tests for code injection vulnerability fix (CWE-94)
  describe('Code injection prevention', () => {
    it('Should reject malicious code injection attempts via preTax field', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt code injection in preTax field
      cy.get('input[name="preTax"]')
        .clear()
        .type('5; require("fs").writeFileSync("/tmp/hacked.txt", "pwned"); 5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // Should handle the injection attempt safely - parseInt will return NaN
      // and the validation will catch it
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')
        .contains(/invalid/i)

      cy.url().should('include', 'contributions')
    })

    it('Should reject process.exit() injection attempt', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt to crash the server with process.exit()
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

      // Should handle safely - parseInt returns NaN
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')

      cy.url().should('include', 'contributions')
    })

    it('Should reject function constructor injection', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Attempt injection using Function constructor pattern
      cy.get('input[name="preTax"]')
        .clear()
        .type('5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('(function() {return 10;})()')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // Should handle safely
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')

      cy.url().should('include', 'contributions')
    })

    it('Should handle arithmetic expression strings safely', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Test that arithmetic expressions are not evaluated
      cy.get('input[name="preTax"]')
        .clear()
        .type('5+5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('3')

      cy.get('input[name="roth"]')
        .clear()
        .type('2')

      cy.get('button[type="submit"]')
        .click()

      // parseInt('5+5') returns 5, so should succeed with 5+3+2=10 (under 30%)
      // Should show success and first value should be 5 (not 10)
      cy.get('tbody > tr > td')
        .eq(1)
        .should('contain', '5')

      cy.url().should('include', 'contributions')
    })

    it('Should handle valid numeric string inputs correctly', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Test valid numeric strings
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

      // Should succeed - total is 25% (under 30%)
      cy.get('.alert-success')
        .should('be.visible')

      cy.get('tbody > tr > td')
        .eq(1)
        .should('contain', '10')

      cy.get('tbody > tr > td')
        .eq(2)
        .should('contain', '8')

      cy.get('tbody > tr > td')
        .eq(3)
        .should('contain', '7')

      cy.url().should('include', 'contributions')
    })

    it('Should reject negative numbers', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('-5')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // Should show validation error for negative numbers
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')
        .contains(/invalid/i)

      cy.url().should('include', 'contributions')
    })

    it('Should reject contributions exceeding 30% total', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('15')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('10')

      cy.get('input[name="roth"]')
        .clear()
        .type('10')

      cy.get('button[type="submit"]')
        .click()

      // Should show error - total is 35% (exceeds 30%)
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')
        .contains(/exceed.*30/i)

      cy.url().should('include', 'contributions')
    })

    it('Should handle non-numeric strings safely', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      cy.get('input[name="preTax"]')
        .clear()
        .type('abc')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // parseInt('abc') returns NaN, should be caught by validation
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')
        .contains(/invalid/i)

      cy.url().should('include', 'contributions')
    })

    it('Should handle special JavaScript values safely', () => {
      cy.userSignIn()
      cy.visitPage('/contributions')

      // Test with 'null', 'undefined', 'NaN' as strings
      cy.get('input[name="preTax"]')
        .clear()
        .type('null')

      cy.get('input[name="afterTax"]')
        .clear()
        .type('5')

      cy.get('input[name="roth"]')
        .clear()
        .type('5')

      cy.get('button[type="submit"]')
        .click()

      // parseInt('null') returns NaN, should be caught by validation
      cy.get('.alert-danger, .alert-info')
        .should('be.visible')

      cy.url().should('include', 'contributions')
    })
  })
})
