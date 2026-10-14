import {
  AccountUpdate,
  Bool,
  Field,
  method,
  PublicKey,
  SmartContract,
  State,
  state,
} from 'o1js';

/** Local registry: the administrator is trusted to choose appropriate roots. */
export class RegistryContract extends SmartContract {
  @state(Field) root = State<Field>();
  @state(PublicKey) administrator = State<PublicKey>();

  /** Configure the signed deployment update; ledger isNew prevents post-deploy use. */
  async initialize(root: Field, administrator: PublicKey): Promise<void> {
    this.account.isNew.requireEquals(Bool(true));
    this.requireSignature();
    this.root.set(root);
    this.administrator.set(administrator);
    AccountUpdate.attachToTransaction(this.self);
  }

  @method async updateRoot(nextRoot: Field): Promise<void> {
    const administrator = this.administrator.getAndRequireEquals();
    this.sender
      .getAndRequireSignature()
      .equals(administrator)
      .assertTrue('sender must be registry administrator');
    this.root.getAndRequireEquals();
    this.root.set(nextRoot);
  }
}
