const Bluebird = require('bluebird');
const Rabbit = require('@chronicled/rabbitmq-adaptor-js/lib/rabbitmq.js');
const Should = require('should');
const Web3 = require('web3');
const dockerCLI = require('docker-cli-js');
const assert = require('assert');
const compose = require('docker-compose');
const Docker =  dockerCLI.Docker;
const docker = new Docker();

const RABBITMQ_URL = 'amqp://guest:guest@localhost:5672';
const ETH_RPC_URL = 'http://localhost:8545';
const EXPECTED_MESSAGES = 100;

const web3 = new Web3(ETH_RPC_URL);


const isParityActive = function() {
  let tries = 10;
  return new Promise(function cb(resolve, reject) {
    web3.eth.getBlock('latest', (err, res) => {
      if (err || res.number < 100) {
        if (--tries > 0) {
          setTimeout(function() {
            cb(resolve, reject);
          }, 5000);
        } else {
          reject('Failure');
        }
      } else {
        resolve(res);
      }
    });
  });
};

describe('Test Blockchain RabbitMQ Interface', function() {
  let rabbit = new Rabbit();

  before(function() {
    this.timeout(300000);
    return compose.upAll({ cwd: '..', config: 'docker-compose.test.yml', log: true })
      .then(isParityActive, err => console.log('docker-compose up error: ', err.message))
      .then(() => rabbit.connect(RABBITMQ_URL));
  });

  it('should send missing blocks', function() {
    this.timeout(6000);
    let message_counter = 0;
    return new Promise(function cb(resolve, reject) {
      rabbit.consume('BlockchainService.NewBlocks', message => {
        message_counter++;
        console.log(message_counter);
        if (message_counter < EXPECTED_MESSAGES) {
          cb(resolve, reject);
        } else {
          resolve();
        }
      });
    });
  })

  it('should stop the Blockchain Interface when RabbitMQ stops', function() {
    this.timeout(30000);
    return compose.stopOne('rabbitmq', { cwd: '..', config: 'docker-compose.test.yml'})
    .then(() => Bluebird.delay(5000), err => Bluebird.reject(err))
    .then(() => {
    return docker.command('ps')
      .then((result) => new Bluebird((resolve, reject) => {
        if (result.containerList.length === 0) {
          resolve();
        } else {
          reject();
        }
      }))
    });
  })

  after(function() {
    compose.down({ cwd: '..', config: 'docker-compose.test.yml', log: true })
  })
});
