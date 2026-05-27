export const createSelectors = (_store) =>{
    const store = _store;
    store.use = {};
    for (const k of Object.keys(store.getState())){
        store.use[k] = () => store((state)=> state[k]);
    }
    return store;
}