describe('client secret test', () => {
  it('can visit the application and can sign in', () => {
    // Visit the test application, the application should redirect to the login page
    cy.visit('http://localhost:8000')

    // Now we should be on the login page, we can check the url if it includes realms
    cy.url().should('include', '/realms/')

    // Set username and password and login
    cy.get('#username').clear('testuser');
    cy.get('#username').type('testuser');
    cy.get('#password').clear();
    cy.get('#password').type('testpassword');
    cy.get('#kc-login').click();

    // After login, we are redirected back to the application
    cy.url().should('contain', 'http://localhost:8000')

    // We should see the username.
    cy.contains('Hi John Doe')
  })
})