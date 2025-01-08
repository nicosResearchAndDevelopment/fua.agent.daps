const
  { describe, test } = require('mocha'),
  expect = require('expect'),
  DAPSAgent = require('../src/agent.daps.js');

describe('agent.daps', function () {

  test('develop', function() {
    console.log(DAPSAgent);
  })

});
