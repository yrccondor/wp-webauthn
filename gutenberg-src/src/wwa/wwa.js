import { TextControl, TextareaControl, CheckboxControl } from "@wordpress/components";

const { __ } = wp.i18n;
const { registerBlockType } = wp.blocks;

registerBlockType("wwa/login", {
    title: __("WebAuthn Login Form", "wwa"),
    icon: "admin-network",
    category: "widgets",
    keywords: ["WebAuthn", __("Login Form", "wwa")],
    attributes: {
        traditional: {
            type: "boolean",
            default: true
        },
        username: {
            type: "string"
        },
        autoHide: {
            type: "boolean",
            default: true
        },
        to: {
            type: "string"
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Login Form", "wwa")}
                </span>
                <TextControl
                    label={__("Default username", "wwa")}
                    value={attributes.username}
                    onChange={val => {
                        setAttributes({ username: val });
                    }}
                />
                <TextControl
                    label={__("Redirect to", "wwa")}
                    value={attributes.to}
                    onChange={val => {
                        setAttributes({ to: val });
                    }}
                />
                <CheckboxControl
                    label={__("Show password form as well", "wwa")}
                    checked={attributes.traditional}
                    onChange={val => {
                        setAttributes({ traditional: val });
                    }}
                />
                <CheckboxControl
                    label={__("Hide for logged-in users", "wwa")}
                    checked={attributes.autoHide}
                    onChange={val => {
                        setAttributes({ autoHide: val });
                    }}
                />
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_login_form traditional="${attributes.traditional}" username="${attributes.username}" auto_hide="${attributes.autoHide}" to="${attributes.to}"]`;
    }
});

registerBlockType("wwa/register", {
    title: __("WebAuthn Register Form", "wwa"),
    icon: "plus-alt",
    category: "widgets",
    keywords: ["WebAuthn", __("Register Form", "wwa")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Register Form", "wwa")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "150px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't loggeg-in", "wwa")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_register_form display="${attributes.display}"]`;
    }
});


registerBlockType("wwa/verify", {
    title: __("WebAuthn Verify Buttons", "wwa"),
    icon: "sos",
    category: "widgets",
    keywords: ["WebAuthn", __("Verify Buttons", "wwa")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Verify Buttons", "wwa")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "50px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't loggeg-in", "wwa")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_verify_button display="${attributes.display}"]`;
    }
});

registerBlockType("wwa/list", {
    title: __("WebAuthn Authenticator List", "wwa"),
    icon: "menu",
    category: "widgets",
    keywords: ["WebAuthn", __("Authenticator List", "wwa")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Authenticator List", "wwa")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "150px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't loggeg-in", "wwa")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_list display="${attributes.display}"]`;
    }
});
