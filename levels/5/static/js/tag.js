// This function is useful for creating a tree structure of HTML elements.
// You can recursively nest calls to tag(...) within the list of children.
// Children can also be strings which will be automatically converted to
// text nodes in the tree.
// I really just thought this was a lot less effort than pulling out a whole
// single page app framework that I'm not as familiar with. Maybe one day
// JSX will be built into browsers.
const tag = function(tagName, opts={attrs: {}, children: [], eventListeners: {}}) {
    // Create the element with the specified tag name
    const element = document.createElement(tagName);

    // Set attributes from the attrs object
    for (const [attrName, attrValue] of Object.entries(opts.attrs || {})) {
        element.setAttribute(attrName, attrValue);
    }

    // Append child elements from the children array
    for (const child of opts.children || []) {
        if (child instanceof Element) {
            element.appendChild(child);
        } else if (typeof child === 'string') {
            // If child is a string, create a text node and append it
            const textNode = document.createTextNode(child);
            element.appendChild(textNode);
        }
        // May add more conditions or handle other types of children as needed
    }

    // Add event listeners.
    for (const [eventName, callback] of Object.entries(opts.eventListeners || {})) {
        element.addEventListener(eventName, callback);
    }

    return element;
};
