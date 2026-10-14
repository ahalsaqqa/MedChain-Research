import { AccountUpdate, Field, Mina, PrivateKey } from 'o1js';
import { RegistryContract } from '../src/RegistryContract.js';

// Mock proofs preserve local transaction/authorization constraints but are not cryptographic evidence.
describe('registry contract (local mock proofs; proofsEnabled=false)', () => {
  async function setup() {
    const local = await Mina.LocalBlockchain({ proofsEnabled: false });
    Mina.setActiveInstance(local);
    const [admin, attacker] = local.testAccounts;
    const key = PrivateKey.random();
    const contract = new RegistryContract(key.toPublicKey());
    const tx = await Mina.transaction(admin, async () => {
      AccountUpdate.fundNewAccount(admin);
      await contract.deploy();
      await contract.initialize(Field(10), admin);
    });
    await tx.prove();
    const pending = await tx.sign([admin.key, key]).send();
    expect((await pending.wait()).status).toBe('included');
    return { local, admin, attacker, contract, key };
  }
  test('deploys once with the specified root and administrator, and authorizes admin updates', async () => {
    const { admin, contract } = await setup();
    expect(contract.root.get().toBigInt()).toBe(10n);
    expect(contract.administrator.get().equals(admin).toBoolean()).toBe(true);
    const tx = await Mina.transaction(admin, async () => {
      await contract.updateRoot(Field(20));
    });
    await tx.prove();
    const pending = await tx.sign([admin.key]).send();
    expect((await pending.wait()).status).toBe('included');
    expect(
      Mina.getAccount(contract.address).zkapp!.appState[0].toBigInt()
    ).toBe(20n);
  });
  test('rejects an unrelated sender and preserves root', async () => {
    const { attacker, contract } = await setup();
    await expect(
      Mina.transaction(attacker, async () => {
        await contract.updateRoot(Field(99));
      })
    ).rejects.toThrow(/administrator/);
    expect(contract.root.get().toBigInt()).toBe(10n);
  });
  test('rejects a second initialize even from the administrator', async () => {
    const { admin, contract, key } = await setup();
    await expect(
      (async () => {
        const tx = await Mina.transaction(admin, async () => {
          await contract.initialize(Field(99), admin);
        });
        await tx.prove();
        await tx.sign([admin.key, key]).send();
      })()
    ).rejects.toThrow(/isNew|precondition|new account/);
    expect(contract.root.get().toBigInt()).toBe(10n);
  });
  test('rejects an update constructed against a superseded root', async () => {
    const { admin, contract } = await setup();
    const stale = await Mina.transaction(
      {
        sender: admin,
        nonce: Number(Mina.getAccount(admin).nonce.toBigint()) + 1,
      },
      async () => {
        await contract.updateRoot(Field(30));
      }
    );
    await stale.prove();
    const current = await Mina.transaction(admin, async () => {
      await contract.updateRoot(Field(20));
    });
    await current.prove();
    await current.sign([admin.key]).send();
    await expect(stale.sign([admin.key]).send()).rejects.toThrow(
      /precondition|app_state/i
    );
    expect(contract.root.get().toBigInt()).toBe(20n);
  });
});
