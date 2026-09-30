import test from 'node:test';
import assert from 'node:assert/strict';
import {captureProfileMethod, speechEventBelongsToSession} from '../src/platform/hubProfileScope.ts';

test('deferred callbacks retain the exact immutable originating selection', async () => {
  const selection = {profileId: 'a', selectionGeneration: 1};
  const calls = [];
  const call = captureProfileMethod(selection, async input => { calls.push(input); });
  selection.profileId = 'b';
  selection.selectionGeneration = 2;
  await call({operation: 'intent.submit', scope: {profileId: 'b', selectionGeneration: 2}});
  assert.deepEqual(calls[0].scope, {profileId: 'a', selectionGeneration: 1});
  assert.equal(Object.isFrozen(calls[0].scope), true);
});

test('A to B to A does not revive old callbacks or create an extra request', async () => {
  let active = {profileId: 'a', selectionGeneration: 1};
  let writes = 0;
  const native = async ({scope}) => {
    if (scope.profileId !== active.profileId || scope.selectionGeneration !== active.selectionGeneration) {
      throw new Error('PROFILE_SELECTION_CHANGED');
    }
    writes++;
  };
  const oldA = captureProfileMethod(active, native);
  active = {profileId: 'b', selectionGeneration: 2};
  const b = captureProfileMethod(active, native);
  active = {profileId: 'a', selectionGeneration: 3};
  await assert.rejects(oldA(), /PROFILE_SELECTION_CHANGED/);
  await assert.rejects(b(), /PROFILE_SELECTION_CHANGED/);
  assert.equal(writes, 0);
  await captureProfileMethod(active, native)();
  assert.equal(writes, 1);
});

test('Network selection invalidates a previous confirmation within the same Hub', async () => {
  const calls = [];
  const old = captureProfileMethod({profileId: 'a', selectionGeneration: 8}, async input => calls.push(input));
  await old({networkId: 'network-a'});
  assert.equal(calls[0].scope.selectionGeneration, 8);
  assert.notEqual(calls[0].scope.selectionGeneration, 9);
});

test('late recording events cannot append text or stop recording in another selection', () => {
  const a = 'profile-a:1:recording-1';
  const b = 'profile-b:2:recording-2';
  assert.equal(speechEventBelongsToSession(b, {sessionId: a, text: 'private transcript'}), false);
  assert.equal(speechEventBelongsToSession(b, {sessionId: a}), false);
  assert.equal(speechEventBelongsToSession(b, {sessionId: b, text: 'current transcript'}), true);
  assert.equal(speechEventBelongsToSession('', {sessionId: a}), false);
  assert.equal(speechEventBelongsToSession(b, {}), false);
});
